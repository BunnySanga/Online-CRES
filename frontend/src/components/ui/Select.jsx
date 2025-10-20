import React from 'react';

export default function Select({label, required, error, children, className='', ...props}){
  return (
    <label className={`block text-sm ${className}`}>
      {label && <span className="block mb-1">{label} {required && <span className="text-red-600">*</span>}</span>}
      <select {...props} className={`border rounded px-3 py-2 w-full bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500 ${error? 'border-red-500':'border-gray-300'}`}>
        {children}
      </select>
      {error && <div className="text-xs text-red-600 mt-1">{error}</div>}
    </label>
  );
}
