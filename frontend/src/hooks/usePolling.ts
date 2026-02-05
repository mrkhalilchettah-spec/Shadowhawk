/**
 * ShadowHawk Platform Polling Hook
 */
"use client";

import { useEffect, useState } from "react";

type PollingState<T> = {
  data: T | null;
  loading: boolean;
  error: string | null;
};

export const usePolling = <T,>(fetcher: () => Promise<T>, intervalMs: number) => {
  const [state, setState] = useState<PollingState<T>>({
    data: null,
    loading: true,
    error: null
  });

  useEffect(() => {
    let isMounted = true;

    const run = async () => {
      try {
        const data = await fetcher();
        if (isMounted) {
          setState({ data, loading: false, error: null });
        }
      } catch (error) {
        if (isMounted) {
          setState({ data: null, loading: false, error: error instanceof Error ? error.message : "Unknown error" });
        }
      }
    };

    run();
    const interval = setInterval(run, intervalMs);

    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, [fetcher, intervalMs]);

  return state;
};
