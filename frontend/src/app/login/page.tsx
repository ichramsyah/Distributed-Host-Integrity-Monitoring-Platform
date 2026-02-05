'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import api from '../lib/api';
import { FaEye, FaEyeSlash } from 'react-icons/fa';
import toast from 'react-hot-toast';

export default function LoginPage() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const router = useRouter();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const data = await api(
        'login/',
        {
          method: 'POST',
          body: JSON.stringify({ username, password }),
        },
        'main'
      );

      if (data.token) {
        localStorage.setItem('jwt_token', data.token);
      }

      toast.success('Login berhasil');
      router.push('/');
      router.refresh();
    } catch (err: any) {
      setError('Username atau password salah.');
    }
  };

  return (
    <div className="bg-background-dark min-h-screen flex items-center justify-center p-4">
      <form className="bg-background-main border border-gray-8/20 md:px-9 px-6 pt-6 pb-8 rounded-lg w-full max-w-[380px]" onSubmit={handleSubmit} autoComplete="off">
        <h1 className="text-center text-gray-2 text-2xl mb-6">Login</h1>
        <div className="relative mb-4">
          {/* Username */}
          <input
            id="username"
            type="text"
            className="block w-full px-3 py-2 text-gray-200 bg-transparent border border-gray-5/50 rounded-md appearance-none peer focus:outline-none focus:ring-0 focus:border-gray-300"
            placeholder=" "
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
            autoComplete="off"
          />
          <label
            htmlFor="username"
            className="absolute text-gray-500 duration-300 transform -translate-y-4 scale-75 top-2 z-10 origin-[0] bg-background-main px-2 left-1 peer-placeholder-shown:scale-100 peer-placeholder-shown:translate-y-0 peer-focus:scale-75 peer-focus:-translate-y-4 peer-focus:text-gray-300"
          >
            Username
          </label>
        </div>

        {/* Password */}
        <div className="relative mb-6">
          <input
            id="password"
            type={showPassword ? 'text' : 'password'}
            className="block w-full px-3 py-2 text-gray-200 bg-transparent border border-gray-5/50 rounded-md appearance-none peer focus:outline-none focus:ring-0 focus:border-gray-300"
            placeholder=" "
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            autoComplete="off"
          />
          <label
            htmlFor="password"
            className="absolute text-gray-500 duration-300 transform -translate-y-4 scale-75 top-2 z-10 origin-[0] bg-background-main px-2 left-1 peer-placeholder-shown:scale-100 peer-placeholder-shown:translate-y-0 peer-focus:scale-75 peer-focus:-translate-y-4 peer-focus:text-gray-300"
          >
            Password
          </label>
          <button type="button" onClick={() => setShowPassword(!showPassword)} className="absolute top-1/2 right-3 -translate-y-1/2 text-gray-300 hover:text-gray-400">
            {showPassword ? <FaEyeSlash size={18} /> : <FaEye size={18} />}
          </button>
        </div>

        {error && <p className="text-red-600 text-sm mb-4">{error}</p>}

        <button type="submit" className="w-full cursor-pointer bg-gray-5/30 text-gray-2 py-2 px-4 rounded-[5px] hover:rounded-[50px] transition-all duration-300">
          Submit
        </button>
      </form>
    </div>
  );
}
