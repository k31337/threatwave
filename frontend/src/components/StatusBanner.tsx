// Floating status overlay for graph-level loading and error feedback. Renders
// nothing when idle.

interface StatusBannerProps {
  loading: boolean;
  error: string | null;
}

export function StatusBanner({ loading, error }: StatusBannerProps) {
  if (!loading && !error) return null;
  const isError = Boolean(error);
  return (
    <div
      className={`status status--${isError ? "error" : "loading"}`}
      role={isError ? "alert" : "status"}
    >
      {isError ? error : "Loading…"}
    </div>
  );
}
