import { defineCredentialProvider } from "@ardia/plugin-sdk";
import { onePassword } from "./provider";

void defineCredentialProvider(onePassword);
