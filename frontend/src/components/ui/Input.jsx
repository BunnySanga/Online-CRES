import React from 'react';

export default function Input({label, required, hint, error, className='', ...props}){
  return (
    <label className={`block text-sm ${className}`}>
      {label && <span className="block mb-1">{label} {required && <span className="text-red-600">*</span>}</span>}
      <input {...props} className={`border rounded px-3 py-2 w-full focus:outline-none focus:ring-2 focus:ring-indigo-500 ${error? 'border-red-500':'border-gray-300'}`} />
      {hint && <div className="text-xs text-gray-500 mt-1">{hint}</div>}
      {error && <div className="text-xs text-red-600 mt-1">{error}</div>}
    </label>
  );
}
