interface Props {
  isUp: boolean | null;
  isDegraded?: boolean;
  small?: boolean;
}

export default function StatusBadge({ isUp, isDegraded = false, small = false }: Props) {
  const size = small ? "px-1.5 py-0.5 text-xs" : "px-2.5 py-1 text-sm";

  if (isUp === null) {
    return (
      <span className={`inline-flex items-center rounded-full font-medium bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300 ${size}`}>
        Pending
      </span>
    );
  }

  if (!isUp) {
    return (
      <span className={`inline-flex items-center gap-1 rounded-full font-medium bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400 ${size}`}>
        <span className="h-1.5 w-1.5 rounded-full bg-red-500 inline-block" />
        Down
      </span>
    );
  }

  if (isDegraded) {
    return (
      <span className={`inline-flex items-center gap-1 rounded-full font-medium bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-400 ${size}`}>
        <span className="h-1.5 w-1.5 rounded-full bg-yellow-500 inline-block" />
        Degraded
      </span>
    );
  }

  return (
    <span className={`inline-flex items-center gap-1 rounded-full font-medium bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400 ${size}`}>
      <span className="h-1.5 w-1.5 rounded-full bg-green-500 inline-block" />
      Up
    </span>
  );
}
