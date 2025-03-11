import bodyParser from "body-parser";
import express from "express";
import { BASE_ONION_ROUTER_PORT, REGISTRY_PORT } from "../config";
import {
    generateRsaKeyPair,
    exportPubKey,
    exportPrvKey,
    rsaDecrypt,
    symDecrypt,
    rsaEncrypt,
    importSymKey,
    exportSymKey,
} from "../crypto";

export async function simpleOnionRouter(nodeId: number) {
    const onionRouter = express();
    onionRouter.use(express.json());
    onionRouter.use(bodyParser.json());

    const { publicKey, privateKey } = await generateRsaKeyPair();
    const pubKeyStr = await exportPubKey(publicKey);
    await fetch(`http://localhost:${REGISTRY_PORT}/registerNode`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ nodeId, pubKey: pubKeyStr }),
    });

    let lastReceivedEncryptedMessage: string | null = null;
    let lastReceivedDecryptedMessage: string | null = null;
    let lastMessageDestination: number | null = null;

    onionRouter.get("/status", (req, res) => {
        res.send("live");
    });

    onionRouter.get("/getLastReceivedEncryptedMessage", (req, res) => {
        res.json({ result: lastReceivedEncryptedMessage });
    });

    onionRouter.get("/getLastReceivedDecryptedMessage", (req, res) => {
        res.json({ result: lastReceivedDecryptedMessage });
    });

    onionRouter.get("/getLastMessageDestination", (req, res) => {
        res.json({ result: lastMessageDestination });
    });

    onionRouter.get("/getPrivateKey", async (req, res) => {
        const prvKeyStr = await exportPrvKey(privateKey);
        res.json({ result: prvKeyStr });
    });

    onionRouter.post("/message", async (req, res) => {
        const { message } = req.body;
        lastReceivedEncryptedMessage = message;

        const delimiterIndex = message.indexOf(":");
        if (delimiterIndex === -1) {
            console.error("Invalid message format");
            res.status(400).send("Invalid message format");
            return;
        }
        const encrypt_symkey = message.slice(0, delimiterIndex);
        const symEncrypt_Payload = message.slice(delimiterIndex + 1);

        const decrypt_keystr = await rsaDecrypt(encrypt_symkey, privateKey);
        const symmetricKey = await importSymKey(decrypt_keystr);

        const decrypt_Layer = await symDecrypt(decrypt_keystr, symEncrypt_Payload);
        lastReceivedDecryptedMessage = decrypt_Layer;

        const destinationStr = decrypt_Layer.slice(0, 10);
        const innerPayload = decrypt_Layer.slice(10);
        const nextDestination = parseInt(destinationStr, 10);
        lastMessageDestination = nextDestination;

        const url = `http://localhost:${nextDestination}/message`;
        await fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ message: innerPayload }),
        });

        res.send("success");
    });

    const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
        console.log(
            `Onion router ${nodeId} is listening on port ${BASE_ONION_ROUTER_PORT + nodeId}`
        );
    });

    return server;
}
