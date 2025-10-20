import React from 'react';
import { NavLink } from 'react-router-dom';

export default function TabLink({ to, children }) {
  const cls = ({ isActive }) => [
    'inline-flex items-center',
    'px-4 py-3',
    'rounded-xl',
    'border transition',
    'text-sm',
    isActive
      ? 'bg-indigo-600 text-white border-indigo-600 shadow-[0_2px_8px_rgba(91,95,204,0.3)]'
      : 'bg-white/80 text-gray-700 border-gray-300 hover:bg-gray-100 hover:border-gray-400 hover:shadow-sm hover:scale-[1.02]'
  ].join(' ');
  return (
    <NavLink to={to} className={cls}>
      {children}
    </NavLink>
  );
}
