import { AlertPayload } from "../types";

export interface ConfigField {
  label: string;
  type: "text" | "password" | "number";
  required: boolean;
  placeholder?: string;
}

export interface INotifier {
  type: string;
  displayName: string;
  configSchema: Record<string, ConfigField>;
  send(config: Record<string, unknown>, payload: AlertPayload): Promise<void>;
}
