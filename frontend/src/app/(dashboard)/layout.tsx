'use client';
import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import DashboardClientLayout from '../components/DashboardClientLayout';
import SkeletonLoader from '../components/SkeletonLoader';
import api from '../lib/api';

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const [isChecking, setIsChecking] = useState(true);

  useEffect(() => {
    const checkAuth = async () => {
      try {
        await api('check-auth/');
        setIsChecking(false);
      } catch (error) {
        console.error('Auth check failed:', error);
        router.push('/login');
      }
    };

    checkAuth();
  }, [router]);

  if (isChecking) return <SkeletonLoader />;

  return <DashboardClientLayout>{children}</DashboardClientLayout>;
}
