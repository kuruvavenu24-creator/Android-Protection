import express from "express";
import multer from "multer";
import fetch from "node-fetch";
import dotenv from "dotenv";
import fs from "fs";
import crypto from "crypto";

dotenv.config();

const app = express();
const upload = multer({ dest: "uploads/" });

app.use(express.static("public"));

async function getReport(hash) {
    const response = await fetch(
        `https://www.virustotal.com/api/v3/files/${hash}`,
        {
            headers: { "x-apikey": process.env.VT_API_KEY }
        }
    );

    return await response.json();
}

async function uploadToVT(filePath) {

    const fileBuffer = fs.readFileSync(filePath);

    const response = await fetch(
        "https://www.virustotal.com/api/v3/files",
        {
            method: "POST",
            headers: {
                "x-apikey": process.env.VT_API_KEY
            },
            body: fileBuffer
        }
    );

    return await response.json();
}

app.post("/scan", upload.single("file"), async (req, res) => {

    try {
        const filePath = req.file.path;

        const fileBuffer = fs.readFileSync(filePath);
        const hash = crypto.createHash("sha256").update(fileBuffer).digest("hex");

        let report = await getReport(hash);

        // If file not found in database
        if (!report.data) {

            console.log("File not found. Uploading to VirusTotal...");

            await uploadToVT(filePath);

            // Wait for analysis (Free API needs delay)
            await new Promise(resolve => setTimeout(resolve, 15000));

            report = await getReport(hash);
        }

        fs.unlinkSync(filePath);

        if (report.data) {
            const stats = report.data.attributes.last_analysis_stats;

            res.json({
                malicious: stats.malicious,
                suspicious: stats.suspicious,
                harmless: stats.harmless,
                undetected: stats.undetected
            });
        } else {
            res.json({ message: "Scan submitted. Please check later." });
        }

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Error during scan." });
    }
});

app.listen(3000, () => {
    console.log("🛡 PDFShield running at http://localhost:3000");
});