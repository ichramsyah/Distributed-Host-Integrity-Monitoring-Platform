// app/components/SkeletonLoader.tsx
import React from 'react';

export default function SkeletonLoader() {
  return (
    <div className="flex min-h-screen w-full items-center justify-center bg-background-dark" role="status">
      <div className="relative h-16 w-16">
        <div
          className="
            absolute h-full w-full rounded-full
            border-4 border-transparent border-t-white
            animate-spin [animation-duration:2s] [animation-direction:reverse]
          "
        ></div>

        <div
          className="
            absolute h-full w-full rounded-full
            border-4 border-transparent border-b-gray-400
            animate-spin [animation-duration:1.2s]
          "
        ></div>
      </div>
    </div>
  );
}
