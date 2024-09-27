const { BlobServiceClient } = require('@azure/storage-blob'); 
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

        const privateKey = Buffer.from(base64PrivateKey, 'base64').toString('utf-8');
       
        context.log(" ##decrypting:");
        const decryptedData = await decryptBlob(myBlob, privateKey, context);

        if (isCSV(decryptedData)) {
            context.log(" ##decrypted data is csv");
        
            let csvBlobName = blobName;
            if (!csvBlobName.endsWith('.csv')) {
                csvBlobName = `${blobName}.csv`;
            }
        
            const blockBlobClient = outputContainerClient.getBlockBlobClient(csvBlobName);
        
            await blockBlobClient.upload(decryptedData, Buffer.byteLength(decryptedData), {
                blobHTTPHeaders: { blobContentType: 'text/csv' } 
            });
        
            context.log(`Decrypted data saved as CSV: ${csvBlobName}`);
        } else {
            context.log(" ##decrypted data is not csv");
        }

        context.log(`Decrypted blob '${blobName}' and moved to output container.`);
    } catch (err) {
        context.log.error(`Error processing blob ${blobName}:`, err);
        throw err;
    }
};

async function decryptBlob(blobContent, privateKeyArmored, context) {
    try {
        const passphrase = process.env.PGP_PRIVATE_KEY_PASSPHRASE;


        context.log(" ##Reading the private key");
        const privateKey = await openpgp.readPrivateKey({ armoredKey: privateKeyArmored });

        context.log(" ##Decrypting the private key with passphrase");
        const decryptedPrivateKey = await openpgp.decryptKey({
            privateKey,
            passphrase
        });

        context.log(" ##Reading the message from the blob content");
        const message = await openpgp.readMessage({
            armoredMessage: blobContent.toString('utf-8') 
        });

        context.log(" ##Decrypting the message");
        const { data: decrypted } = await openpgp.decrypt({
            message,
            decryptionKeys: decryptedPrivateKey 
        });

        context.log(" ##Message decrypted successfully");
        return decrypted; 
    } catch (err) {
        context.log.error("Error during decryption:", err);
        throw err; 
    }
}


function isCSV(content) {

    const contentStr = content.toString('utf-8');
    
    const lines = contentStr.split('\n');

    for (let i = 0; i < Math.min(10, lines.length); i++) {
        const line = lines[i].trim();
        if (line.length === 0) continue; 

        const delimiters = [',', ';', '\t'];
        let delimiterFound = false;
        for (const delimiter of delimiters) {
            if (line.includes(delimiter)) {
                delimiterFound = true;
                break;
            }
        }

        if (!delimiterFound) {
            return false;
        }

        const columns = line.split(/[,;\t]/).length;
        if (i > 0 && columns !== lines[0].split(/[,;\t]/).length) {
            return false;
        }
    }
    
    return true; 
}

