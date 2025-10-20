import React from 'react';

const STYLES = {
  info: 'bg-blue-50 text-blue-800 border-blue-200',
  success: 'bg-emerald-50 text-emerald-800 border-emerald-200',
  warning: 'bg-yellow-50 text-yellow-800 border-yellow-200',
  danger: 'bg-red-50 text-red-800 border-red-200',
};

export default function Alert({kind='info', title, children, className=''}){
  return (
    <div className={`border rounded p-3 ${STYLES[kind]} ${className}`}>
      {title && <div className="font-semibold mb-1">{title}</div>}
      <div className="text-sm">{children}</div>
    </div>
  );
}
