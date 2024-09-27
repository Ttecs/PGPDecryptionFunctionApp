const { BlobServiceClient } = require('@azure/storage-blob'); // Import the BlobServiceClient from the SDK
const openpgp = require('openpgp');

module.exports = async function (context, myBlob) {
    context.log("JavaScript blob trigger function processed blob \n Blob:", context.bindingData.blobTrigger, "\n Blob Size:", myBlob.length, "Bytes");
    const blobName = context.bindingData.name;
    context.log(" ##blob trigger function :", context.bindingData.name);
    
    const outputContainer = "decrypted";
    const connectionString = process.env.DESTINATION_STORAGE;

    const base64PrivateKey = process.env.PGP_PRIVATE_KEY_BASE64;

    context.log(" ##base64PrivateKey :", base64PrivateKey);
    context.log(" ##connectionString :", connectionString);

    context.log(" ##start to connect to BlobServiceClient");

    const blobServiceClient = BlobServiceClient.fromConnectionString(connectionString);
    const outputContainerClient = blobServiceClient.getContainerClient(outputContainer);
    context.log(" ##connected BlobServiceClient:", outputContainerClient.getBlockBlobClient(blobName));

    try {
        // Decode private key from base64
        const privateKey = Buffer.from(base64PrivateKey, 'base64').toString('utf-8');
       

        // Decrypt the blob content
        context.log(" ##decrypting:");
        const decryptedData = await decryptBlob(myBlob, privateKey, context);

        //check decrypted data is csv or not
        if (isCSV(decryptedData)) {
            context.log(" ##decrypted data is csv");
        
            // Ensure the file is saved with the .csv extension
            let csvBlobName = blobName;
            if (!csvBlobName.endsWith('.csv')) {
                csvBlobName = `${blobName}.csv`; // Append .csv if it’s not present
            }
        
            // Get a reference to the blob in the output container
            const blockBlobClient = outputContainerClient.getBlockBlobClient(csvBlobName);
        
            // Upload the decrypted data as a CSV file
            await blockBlobClient.upload(decryptedData, Buffer.byteLength(decryptedData), {
                blobHTTPHeaders: { blobContentType: 'text/csv' } // Set the MIME type for CSV
            });
        
            context.log(`Decrypted data saved as CSV: ${csvBlobName}`);
        } else {
            context.log(" ##decrypted data is not csv");
        }

        // // Upload decrypted file to output container
        // const blockBlobClient = outputContainerClient.getBlockBlobClient(blobName);
        // await blockBlobClient.upload(decryptedData, Buffer.byteLength(decryptedData));

        context.log(`Decrypted blob '${blobName}' and moved to output container.`);
    } catch (err) {
        context.log.error(`Error processing blob ${blobName}:`, err);
        throw err;
    }
};

async function decryptBlob(blobContent, privateKeyArmored, context) {
    try {
        const passphrase = process.env.PGP_PRIVATE_KEY_PASSPHRASE;

        // Read the private key
        context.log(" ##Reading the private key");
        const privateKey = await openpgp.readPrivateKey({ armoredKey: privateKeyArmored });

        // Decrypt the private key with the passphrase
        context.log(" ##Decrypting the private key with passphrase");
        const decryptedPrivateKey = await openpgp.decryptKey({
            privateKey,
            passphrase
        });

        // Read the PGP message from the blob content
        context.log(" ##Reading the message from the blob content");
        const message = await openpgp.readMessage({
            armoredMessage: blobContent.toString('utf-8') // Convert buffer to string for ASCII-armored message
        });

        // Decrypt the message using the decrypted private key
        context.log(" ##Decrypting the message");
        const { data: decrypted } = await openpgp.decrypt({
            message,
            decryptionKeys: decryptedPrivateKey // Use the decrypted private key
        });

        context.log(" ##Message decrypted successfully");
        return decrypted; // Return decrypted data
    } catch (err) {
        context.log.error("Error during decryption:", err);
        throw err; // Rethrow error for higher-level handling
    }
}

// A simple function to check if the content is likely to be a CSV
function isCSV(content) {
    // Convert the content to a string if it's in Buffer format
    const contentStr = content.toString('utf-8');
    
    // Split content by lines
    const lines = contentStr.split('\n');

    // Check first few lines for CSV structure
    for (let i = 0; i < Math.min(10, lines.length); i++) {
        const line = lines[i].trim();
        if (line.length === 0) continue; // Skip empty lines

        // CSV typically has commas or other delimiters
        const delimiters = [',', ';', '\t'];
        let delimiterFound = false;
        for (const delimiter of delimiters) {
            if (line.includes(delimiter)) {
                delimiterFound = true;
                break;
            }
        }

        // If we found no valid delimiter, it's likely not a CSV
        if (!delimiterFound) {
            return false;
        }

        // Ensure rows have consistent number of columns
        const columns = line.split(/[,;\t]/).length;
        if (i > 0 && columns !== lines[0].split(/[,;\t]/).length) {
            return false;
        }
    }
    
    return true; // Passed basic CSV checks
}
