import bodyParser from "body-parser";
import express, { Request, Response } from "express";
import { REGISTRY_PORT } from "../config";

export type Node = { nodeId: number; pubKey: string };

export type RegisterNodeBody = {
    nodeId: number;
    pubKey: string;
};

export type GetNodeRegistryBody = {
    nodes: Node[];
};

export async function launchRegistry() {
    const _registry = express();
    _registry.use(express.json());
    _registry.use(bodyParser.json());

    _registry.get("/status", (req, res) => {
        res.send("live");
    });

    const nodes: Node[] = [];

    _registry.post("/registerNode", (req: Request, res: Response) => {
        const { nodeId, pubKey } = req.body as RegisterNodeBody;
        if (!nodes.some(n => n.nodeId === nodeId)) {
            nodes.push({ nodeId, pubKey });
        }
        res.send("success");
    });

    _registry.get("/getNodeRegistry", (req, res) => {
        res.json({ nodes });
    });

    const server = _registry.listen(REGISTRY_PORT, () => {
        console.log(`registry is listening on port ${REGISTRY_PORT}`);
    });

    return server;
}
