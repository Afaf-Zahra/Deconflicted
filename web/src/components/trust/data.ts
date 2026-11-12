import { useEffect, useState } from "react";
import type {
  DecoysData,
  GraphData,
  Incident,
  LedgerEntry,
  LedgerNode,
  LedgerVerify,
  ResponsePreview,
} from "./types";

const API_MODE = import.meta.env.VITE_API ?? "mock";

export type DataState<T> = {
  data: T | null;
  loading: boolean;
  error: string | null;
};

async function getMock<T>(file: string): Promise<T> {
  const response = await fetch(`/mock/${file}.json`);

  if (!response.ok) {
    throw new Error(`Failed to load mock data: ${response.status}`);
  }

  return response.json() as Promise<T>;
}

async function getLive<T>(path: string): Promise<T> {
  const response = await fetch(path);

  if (!response.ok) {
    throw new Error(`Request failed: ${response.status}`);
  }

  return response.json() as Promise<T>;
}

function useData<T>(
  loader: () => Promise<T>,
  dependencies: unknown[] = [],
): DataState<T> {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;

    setLoading(true);
    setError(null);

    loader()
      .then((result) => {
        if (active) {
          setData(result);
        }
      })
      .catch((err: unknown) => {
        if (active) {
          setError(
            err instanceof Error ? err.message : "Failed to load data",
          );
        }
      })
      .finally(() => {
        if (active) {
          setLoading(false);
        }
      });

    return () => {
      active = false;
    };
  }, dependencies);

  return { data, loading, error };
}

export function useGraph(incidentId: string): DataState<GraphData> {
  return useData(
    async () => {
      if (API_MODE === "mock") {
        const graphs = await getMock<Record<string, GraphData>>("graph");
        const graph = graphs[incidentId];

        if (!graph) {
          throw new Error(`Graph not found for incident ${incidentId}`);
        }

        return graph;
      }

      return getLive<GraphData>(`/incidents/${incidentId}/graph`);
    },
    [incidentId],
  );
}

export function useIncident(incidentId: string): DataState<Incident> {
  return useData(
    async () => {
      if (API_MODE === "mock") {
        const incidents = await getMock<Incident[]>("incidents");
        const incident = incidents.find((item) => item.id === incidentId);

        if (!incident) {
          throw new Error(`Incident not found: ${incidentId}`);
        }

        return incident;
      }

      return getLive<Incident>(`/incidents/${incidentId}`);
    },
    [incidentId],
  );
}

export async function previewResponse(
  actionId: string,
): Promise<ResponsePreview> {
  if (API_MODE === "mock") {
    return getMock<ResponsePreview>("preview");
  }

  const response = await fetch("/response/preview", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ action_id: actionId }),
  });

  if (!response.ok) {
    throw new Error(`Preview request failed: ${response.status}`);
  }

  return response.json() as Promise<ResponsePreview>;
}

export function useLedger(): DataState<LedgerEntry[]> {
  return useData(
    () =>
      API_MODE === "mock"
        ? getMock<LedgerEntry[]>("ledger")
        : getLive<LedgerEntry[]>("/ledger"),
    [],
  );
}

export function useLedgerVerify(): DataState<LedgerVerify> {
  return useData(
    () =>
      API_MODE === "mock"
        ? getMock<LedgerVerify>("verify")
        : getLive<LedgerVerify>("/ledger/verify"),
    [],
  );
}

export function useLedgerNodes(): DataState<LedgerNode[]> {
  return useData(
    () =>
      API_MODE === "mock"
        ? getMock<LedgerNode[]>("nodes")
        : getLive<LedgerNode[]>("/ledger/nodes"),
    [],
  );
}

export function useDecoys(): DataState<DecoysData> {
  return useData(
    () =>
      API_MODE === "mock"
        ? getMock<DecoysData>("decoys")
        : getLive<DecoysData>("/decoys"),
    [],
  );
}
