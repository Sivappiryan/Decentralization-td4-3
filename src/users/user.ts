import bodyParser from "body-parser";
import express from "express";
import { BASE_USER_PORT, BASE_ONION_ROUTER_PORT, REGISTRY_PORT } from "../config";
import { GetNodeRegistryBody } from "../registry/registry";
import {
    createRandomSymmetricKey,
    exportSymKey,
    importSymKey,
    rsaEncrypt,
    symEncrypt,
} from "../crypto";

export type SendMessageBody = {
    message: string;
    destinationUserId: number;
};

export async function user(userId: number) {
    const _user = express();
    _user.use(express.json());
    _user.use(bodyParser.json());

    let lastReceivedMessage: string | null = null;
    let lastSentMessage: string | null = null;
    let lastCircuit: number[] = [];

    _user.get("/status", (req, res) => {
        res.send("live");
    });

    _user.get("/getLastReceivedMessage", (req, res) => {
        res.json({ result: lastReceivedMessage });
    });

    _user.get("/getLastSentMessage", (req, res) => {
        res.json({ result: lastSentMessage });
    });

    _user.get("/getLastCircuit", (req, res) => {
        res.json({ result: lastCircuit });
    });

    _user.post("/message", (req, res) => {
        const { message } = req.body;
        lastReceivedMessage = message;
        res.send("success");
    });

    _user.post("/sendMessage", async (req, res) => {
        const { message, destinationUserId } = req.body as SendMessageBody;
        lastSentMessage = message;

        const registry_response = await fetch(`http://localhost:${REGISTRY_PORT}/getNodeRegistry`);
        const registry_data = (await registry_response.json()) as GetNodeRegistryBody;
        const nodes = registry_data.nodes as { nodeId: number; pubKey: string }[];

        if (nodes.length < 3) {
            res.status(500).send("Not enough nodes registered");
            return;
        }
        const shuffled = nodes.sort(() => Math.random() - 0.5);
        const circuitNodes = shuffled.slice(0, 3);
        lastCircuit = circuitNodes.map((node) => node.nodeId);

        let payload = message;

        for (let i = circuitNodes.length - 1; i >= 0; i--) {
            const currentNode = circuitNodes[i];

            let destinationPort: number;
            if (i === circuitNodes.length - 1) {
                destinationPort = BASE_USER_PORT + destinationUserId;
            } else {
                destinationPort = BASE_ONION_ROUTER_PORT + circuitNodes[i + 1].nodeId;
            }
            const destStr = destinationPort.toString().padStart(10, "0");

            const layeredMessage = destStr + payload;

            const symKey = await createRandomSymmetricKey();

            const symEncrypt_Payload = await symEncrypt(symKey, layeredMessage);

            const exportedSymKey = await exportSymKey(symKey);

            const encrypt_symkey = await rsaEncrypt(exportedSymKey, currentNode.pubKey);

            payload = encrypt_symkey + ":" + symEncrypt_Payload;
        }

        const entry_port_node = BASE_ONION_ROUTER_PORT + circuitNodes[0].nodeId;
        await fetch(`http://localhost:${entry_port_node}/message`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ message: payload }),
        });

        res.send("success");
    });

    const server = _user.listen(BASE_USER_PORT + userId, () => {
        console.log(
            `User ${userId} is listening on port ${BASE_USER_PORT + userId}`
        );
    });

    return server;
}
