import express from "express";
import multer from "multer";
import fetch from "node-fetch";
import dotenv from "dotenv";
import fs from "fs";
import crypto from "crypto";
import path from "path";

dotenv.config();

const app = express();
const upload = multer({ dest: "uploads/" });

app.use(express.static("public"));

app.post("/scan", upload.single("file"), async (req, res) => {

    try {
        const filePath = req.file.path;

        // Create SHA256 hash
        const fileBuffer = fs.readFileSync(filePath);
        const hash = crypto.createHash("sha256").update(fileBuffer).digest("hex");

        // Query VirusTotal
        const response = await fetch(
            `https://www.virustotal.com/api/v3/files/${hash}`,
            {
                headers: {
                    "x-apikey": process.env.VT_API_KEY
                }
            }
        );

        const data = await response.json();

        fs.unlinkSync(filePath); // delete uploaded file

        if (data.data) {
            const stats = data.data.attributes.last_analysis_stats;

            res.json({
                malicious: stats.malicious,
                suspicious: stats.suspicious,
                harmless: stats.harmless,
                undetected: stats.undetected
            });
        } else {
            res.json({ message: "File not found in VirusTotal database." });
        }

    } catch (error) {
        res.status(500).json({ error: "Error scanning file." });
    }
});

app.listen(3000, () => {
    console.log("🛡 PDFShield running at http://localhost:3000");
});