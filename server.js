const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
const crypto = require('crypto');
const bodyParser = require('body-parser');
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();
const app = express();

const STORAGE_ROOT = 'storage';
const ADMIN_API_KEY = 'super-secret-admin-key';

const STORAGE_LIMITS = {
  free: 1024 * 1024 * 1024, 
};

// Ensure the storage root exists
fs.mkdir(STORAGE_ROOT, { recursive: true }).catch(console.error);

function authenticateAdmin(req, res, next) {
    const adminApiKey = req.header('X-Admin-API-Key');
    if (adminApiKey !== ADMIN_API_KEY) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    next();
}

async function authenticateRequest(req, res, next) {
    const accessId = req.header('X-Access-ID');
    const signature = req.header('X-Signature');
    const timestamp = req.header('X-Timestamp');

    if (!accessId || !signature || !timestamp) {
        return res.status(401).json({ error: 'Missing authentication headers' });
    }

    const apiKey = await prisma.apiKey.findUnique({ where: { accessKeyId: accessId } });
    if (!apiKey) {
        return res.status(401).json({ error: 'Invalid Access ID' });
    }

    // Check if the timestamp is within 15 minutes
    const fifteenMinutesAgo = Date.now() - 15 * 60 * 1000;
    if (parseInt(timestamp) < fifteenMinutesAgo) {
        return res.status(401).json({ error: 'Request expired' });
    }

    const computedSignature = crypto
        .createHmac('sha256', apiKey.secretAccessKey)
        .update(`${req.method}${req.originalUrl}${timestamp}`)
        .digest('hex');

    if (computedSignature !== signature) {
        return res.status(401).json({ error: 'Invalid signature' });
    }

    // Set user-specific storage root and ensure it exists
    req.userStorageRoot = path.join(STORAGE_ROOT, accessId);
    await fs.mkdir(req.userStorageRoot, { recursive: true });

    next();
}

app.use(bodyParser.json());
app.use(bodyParser.raw({ type: '*/*', limit: '10mb' }));

const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// Admin API to create access keys
app.post('/admin/create-access-key', authenticateAdmin, async (req, res) => {
    const { plan = 'free' } = req.body;
    const accessKeyId = crypto.randomBytes(16).toString('hex');
    const secretAccessKey = crypto.randomBytes(32).toString('base64');
    
    const apiKey = await prisma.apiKey.create({
        data: {
            accessKeyId,
            secretAccessKey,
            plan
        }
    });
    
    res.json({ accessKeyId: apiKey.accessKeyId, secretAccessKey: apiKey.secretAccessKey, plan: apiKey.plan });
});

// Admin API to create a bucket
app.post('/admin/create-bucket', authenticateAdmin, async (req, res) => {
    const { accessKeyId, bucketName } = req.body;
    
    if (!accessKeyId || !bucketName) {
        return res.status(400).json({ error: 'Missing accessKeyId or bucketName' });
    }
    
    const apiKey = await prisma.apiKey.findFirst({ where: { accessKeyId } });
    if (!apiKey) {
        return res.status(404).json({ error: 'Access key not found' });
    }
    
    const userStorageRoot = path.join(STORAGE_ROOT, accessKeyId);
    const bucketPath = path.join(userStorageRoot, bucketName);
    
    try {
        await fs.mkdir(bucketPath, { recursive: true });
        await prisma.bucket.create({
            data: {
                name: bucketName,
                accessKeyId
            }
        });
        res.json({ message: 'Bucket created successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to create bucket' });
    }
});

// Existing routes
app.use(authenticateRequest);

async function bucketExists(accessKeyId, bucketName) {
    const bucket = await prisma.bucket.findFirst({
        where: {
            name: bucketName,
            accessKeyId
        }
    });
    return !!bucket;
}

async function checkStorageLimit(accessKeyId, fileSize) {
    const apiKey = await prisma.apiKey.findUnique({ where: { accessKeyId } });
    if (!apiKey) {
        throw new Error('Invalid Access ID');
    }

    const newStorageUsed = apiKey.storageUsed + BigInt(fileSize);
    if (newStorageUsed > STORAGE_LIMITS[apiKey.plan]) {
        throw new Error('Storage limit exceeded');
    }

    await prisma.apiKey.update({
        where: { accessKeyId },
        data: { storageUsed: newStorageUsed }
    });
}

app.post('/buckets/:bucketName/objects', upload.single('file'), async (req, res) => {
    const { bucketName } = req.params;
    const accessKeyId = req.header('X-Access-ID');
    const bucketPath = path.join(req.userStorageRoot, bucketName);

    if (!(await bucketExists(accessKeyId, bucketName))) {
        return res.status(404).json({ error: 'Bucket not found' });
    }

    try {
        let fileName, filePath, fileSize;

        if (req.file) {
            fileName = req.file.originalname;
            filePath = path.join(bucketPath, fileName);
            fileSize = req.file.size;
            await checkStorageLimit(accessKeyId, fileSize);
            await fs.writeFile(filePath, req.file.buffer);
        } else if (req.body) {
            fileName = req.header('X-File-Name');
            if (!fileName) {
                return res.status(400).json({ error: 'X-File-Name header is required for raw data uploads' });
            }
            filePath = path.join(bucketPath, fileName);
            fileSize = req.body.length;
            await checkStorageLimit(accessKeyId, fileSize);
            await fs.writeFile(filePath, req.body);
        } else {
            return res.status(400).json({ error: 'No file or data uploaded' });
        }

        const fileContent = await fs.readFile(filePath);
        const etag = crypto.createHash('md5').update(fileContent).digest('hex');

        res.status(201).json({ ETag: etag });
    } catch (error) {
        console.error(error);
        if (error.message === 'Storage limit exceeded') {
            res.status(403).json({ error: 'Storage limit exceeded' });
        } else {
            res.status(500).json({ error: 'Failed to save data' });
        }
    }
});

app.get('/buckets/:bucketName/objects/:objectKey', async (req, res) => {
    const { bucketName, objectKey } = req.params;
    const accessKeyId = req.header('X-Access-ID');
    const filePath = path.join(req.userStorageRoot, bucketName, objectKey);

    if (!(await bucketExists(accessKeyId, bucketName))) {
        return res.status(404).json({ error: 'Bucket not found' });
    }

    try {
        await fs.access(filePath);
        res.sendFile(filePath);
    } catch (error) {
        res.status(404).json({ error: 'Object not found' });
    }
});

app.delete('/buckets/:bucketName/objects/:objectKey', async (req, res) => {
    const { bucketName, objectKey } = req.params;
    const accessKeyId = req.header('X-Access-ID');
    const filePath = path.join(req.userStorageRoot, bucketName, objectKey);

    if (!(await bucketExists(accessKeyId, bucketName))) {
        return res.status(404).json({ error: 'Bucket not found' });
    }

    try {
        const fileStats = await fs.stat(filePath);
        await fs.unlink(filePath);
        
        // Update storage used
        await prisma.apiKey.update({
            where: { accessKeyId },
            data: {
                storageUsed: {
                    decrement: fileStats.size
                }
            }
        });
        
        res.status(204).send();
    } catch (error) {
        res.status(404).json({ error: 'Object not found' });
    }
});

app.get('/buckets', async (req, res) => {
    const accessKeyId = req.header('X-Access-ID');
    try {
        const buckets = await prisma.bucket.findMany({
            where: { accessKeyId },
            select: { name: true }
        });
        res.json({ Buckets: buckets.map(bucket => ({ Name: bucket.name })) });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to list buckets' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

// Gracefully close the Prisma connection when the server shuts down
process.on('SIGINT', async () => {
    await prisma.$disconnect();
    process.exit();
});