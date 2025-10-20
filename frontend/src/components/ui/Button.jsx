import React from 'react';

const VARIANTS = {
  primary: 'bg-indigo-600 hover:bg-indigo-700 text-white',
  secondary: 'bg-white border border-gray-300 text-gray-800 hover:bg-gray-50',
  danger: 'bg-red-600 hover:bg-red-700 text-white',
  ghost: 'bg-transparent text-gray-700 hover:bg-gray-100',
};

const SIZES = {
  sm: 'px-3 py-1.5 text-sm',
  md: 'px-4 py-2 text-sm',
  lg: 'px-5 py-3',
};

export default function Button({
  children,
  variant = 'primary',
  size = 'md',
  className = '',
  loading = false,
  disabled,
  ...props
}){
  const cn = `inline-flex items-center justify-center rounded transition focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 ${VARIANTS[variant]} ${SIZES[size]} ${className}`;
  return (
    <button className={cn} disabled={disabled || loading} {...props}>
      {loading && (
        <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-current" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z"></path>
        </svg>
      )}
      {children}
    </button>
  );
}
