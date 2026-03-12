// scripts/chatgpt/services/file-upload.js
// File upload service for ChatGPT image analysis
// Handles: initiate upload → PUT file to Azure → process upload stream

class FileUpload {
    /**
     * Initiate a file upload and get the upload URL + file ID.
     *
     * @param {string} proxyUrl   — SOCKS5 proxy URL
     * @param {object} fp         — Fingerprint snapshot
     * @param {object} headers    — Base headers from Headers.build()
     * @param {string} fileName   — Original file name
     * @param {number} fileSize   — File size in bytes
     * @returns {{ upload_url: string, file_id: string }}
     */
    static async initiateUpload(proxyUrl, fp, headers, fileName, fileSize) {
        console.log('[FileUpload] Initiating upload for: ' + fileName + ' (' + fileSize + ' bytes)');

        var body = JSON.stringify({
            file_name: fileName,
            file_size: fileSize,
            use_case: 'multimodal',
            timezone_offset_min: -420,
            reset_rate_limits: false
        });

        var resp = await fetch('https://chatgpt.com/backend-anon/files', {
            method: 'POST',
            fingerprint: fp,
            agent: proxyUrl,
            headers: headers,
            body: body
        });

        if (!resp.ok) {
            throw new Error('Upload initiation failed: HTTP ' + resp.status + ' — ' + (resp.body || '').substring(0, 200));
        }

        var result = JSON.parse(resp.body);
        console.log('[FileUpload] ✅ Upload initiated — file_id: ' + result.file_id);

        return {
            upload_url: result.upload_url,
            file_id: result.file_id,
            fp: resp.fingerprint.snapshoot()
        };
    }

    /**
     * Upload raw file data to the Azure Blob upload URL.
     * fileData is a Uint8Array (from Crypto.Base64Decode or resp.bodyBytes).
     * Go's fetch receives []byte from Uint8Array export — raw binary, no corruption.
     *
     * @param {string} uploadURL     — Azure Blob upload URL from initiateUpload
     * @param {Uint8Array} fileData  — Raw file bytes
     * @param {string} mimeType      — MIME type (e.g. 'image/png')
     */
    static async uploadFile(uploadURL, fileData, mimeType) {
        console.log('[FileUpload] Uploading file data (' + fileData.length + ' bytes, type: ' + mimeType + ')...');

        var resp = await fetch(uploadURL, {
            method: 'PUT',
            headers: {
                'Content-Type': mimeType,
                'x-ms-version': '2020-04-08',
                'x-ms-blob-type': 'BlockBlob'
            },
            body: fileData
        });

        if (!resp.ok && resp.status !== 201) {
            throw new Error('File upload failed: HTTP ' + resp.status + ' — ' + (resp.body || '').substring(0, 200));
        }

        console.log('[FileUpload] ✅ File uploaded to Azure Blob');
    }

    /**
     * Process the uploaded file (server-side processing).
     *
     * @param {string} proxyUrl   — SOCKS5 proxy URL
     * @param {object} fp         — Fingerprint snapshot
     * @param {object} headers    — Base headers from Headers.build()
     * @param {string} fileID     — File ID from initiateUpload
     * @param {string} fileName   — Original file name
     */
    static async processUpload(proxyUrl, fp, headers, fileID, fileName) {
        console.log('[FileUpload] Processing upload for file_id: ' + fileID);

        var body = JSON.stringify({
            file_id: fileID,
            use_case: 'multimodal',
            index_for_retrieval: false,
            file_name: fileName
        });

        var resp = await fetch('https://chatgpt.com/backend-anon/files/process_upload_stream', {
            method: 'POST',
            fingerprint: fp,
            agent: proxyUrl,
            headers: headers,
            body: body
        });

        if (!resp.ok) {
            throw new Error('Process upload failed: HTTP ' + resp.status + ' — ' + (resp.body || '').substring(0, 200));
        }

        var responseBody = resp.body || '';

        // Check if processing completed successfully
        if (responseBody.indexOf('file.processing.completed') === -1) {
            throw new Error('File processing did not complete successfully: ' + responseBody.substring(0, 300));
        }

        console.log('[FileUpload] ✅ File processing completed');
        return resp.fingerprint.snapshoot();
    }
}

module.exports = FileUpload;
