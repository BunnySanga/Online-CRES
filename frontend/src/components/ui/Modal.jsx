import React from 'react';

export default function Modal({open, onClose, title, children, footer}){
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/30" onClick={onClose} />
      <div className="relative bg-white rounded shadow-lg w-[90%] max-w-lg mx-auto p-4">
        {title && <div className="text-lg font-semibold mb-2">{title}</div>}
        <div className="text-sm">{children}</div>
        {footer && <div className="mt-4 flex justify-end gap-2">{footer}</div>}
      </div>
    </div>
  );
}
