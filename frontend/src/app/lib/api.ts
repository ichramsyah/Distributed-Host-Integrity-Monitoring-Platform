// lib/api.ts

const API_SERVERS = {
  main: process.env.NEXT_PUBLIC_API_MAIN,
  server2: process.env.NEXT_PUBLIC_API_SERVER2,
  server3: process.env.NEXT_PUBLIC_API_SERVER3,
  server4: process.env.NEXT_PUBLIC_API_SERVER4,
  server5: process.env.NEXT_PUBLIC_API_SERVER5,
};

export type ApiServerKey = keyof typeof API_SERVERS;

const api = async (endpoint: string, options: RequestInit = {}, server: ApiServerKey = 'main') => {
  const baseUrl = API_SERVERS[server];

  if (!baseUrl) {
    throw new Error(`API Base URL untuk server "${server}" belum dikonfigurasi.`);
  }

  const token = typeof window !== 'undefined' ? localStorage.getItem('jwt_token') : null;

  const defaultOptions: RequestInit = {
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...options.headers,
    },
  };

  const response = await fetch(`${baseUrl}/${endpoint}`, {
    ...defaultOptions,
    ...options,
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ message: response.statusText }));
    throw new Error(errorData.message || `Error ${response.status}`);
  }

  if (response.headers.get('Content-Type')?.includes('application/json')) {
    return response.json();
  }

  return response;
};

export default api;
