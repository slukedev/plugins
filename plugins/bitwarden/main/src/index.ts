import { defineCredentialProvider } from "@ardia/plugin-sdk";
import { bitwarden } from "./provider";

void defineCredentialProvider(bitwarden);
