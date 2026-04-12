interface AppConfig {
  port: number;
  host: string;
  debug: boolean;
}

function calculateTotal(items: number[]): number {
  return items.reduce((sum, item) => sum + item, 0);
}

const config: AppConfig = {
  port: 3000,
  host: "localhost",
  debug: false,
};

export function formatDate(timestamp: number): string {
  return new Date(timestamp).toISOString();
}
