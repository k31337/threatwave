// On-demand narrative state. The narrative is the only AI call the UI makes at
// query time (extraction/embeddings happen at ingestion), so it is explicitly
// user-triggered here — never fired automatically on selection.

import { useCallback, useState } from "react";
import { narrative } from "../api/client";
import { describeError } from "../api/errors";
import type { Narrative } from "../api/types";

export interface UseNarrative {
  data: Narrative | null;
  loading: boolean;
  error: string | null;
  explain: (ioc: string) => Promise<void>;
  clear: () => void;
}

export function useNarrative(): UseNarrative {
  const [data, setData] = useState<Narrative | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const explain = useCallback(async (ioc: string) => {
    setLoading(true);
    setError(null);
    setData(null);
    try {
      setData(await narrative(ioc));
    } catch (err) {
      setError(
        describeError(err, {
          notFound: "This indicator is not in the graph.",
          disabled: "Narrative generation is disabled on this server (no LLM configured).",
        }),
      );
    } finally {
      setLoading(false);
    }
  }, []);

  const clear = useCallback(() => {
    setData(null);
    setError(null);
  }, []);

  return { data, loading, error, explain, clear };
}
