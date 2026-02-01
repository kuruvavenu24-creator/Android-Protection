const express = require("express");
const multer = require("multer");
const path = require("path");

const app = express();

// Serve frontend
app.use(express.static("public"));

// Upload folder access
app.use("/uploads", express.static("uploads"));

// Storage configuration
const storage = multer.diskStorage({
  destination: "uploads/",
  filename: (req, file, cb) => {
    cb(null, Date.now() + "-" + file.originalname);
  }
});

// Only PDF allowed
const fileFilter = (req, file, cb) => {
  if (file.mimetype === "application/pdf") {
    cb(null, true);
  } else {
    cb("Only PDF files allowed!", false);
  }
};

const upload = multer({ storage, fileFilter });

// Upload Route
app.post("/upload", upload.single("pdfFile"), (req, res) => {
  res.json({
    message: "✅ PDF Uploaded Successfully!",
    file: req.file.filename
  });
});

// Server Start
app.listen(3000, () => {
  console.log("🔥 Server running at: http://localhost:3000");
});
