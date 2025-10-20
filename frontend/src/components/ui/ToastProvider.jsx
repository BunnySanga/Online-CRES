import React, { createContext, useContext, useState, useCallback } from 'react';

const ToastContext = createContext({ push: ()=>{} });

export function ToastProvider({children}){
  const [toasts, setToasts] = useState([]);
  const push = useCallback((message, kind='info') => {
    const id = Math.random().toString(36).slice(2);
    setToasts(prev => [...prev, { id, message, kind }]);
    setTimeout(()=> setToasts(prev => prev.filter(t=>t.id!==id)), 3500);
  }, []);
  return (
    <ToastContext.Provider value={{ push }}>
      {children}
      <div className="fixed bottom-4 right-4 space-y-2 z-50">
        {toasts.map(t => (
          <div key={t.id} className={`px-4 py-2 rounded shadow text-white text-sm ${t.kind==='success'?'bg-emerald-600': t.kind==='danger'?'bg-red-600': t.kind==='warning'?'bg-yellow-600':'bg-indigo-600'}`}>{t.message}</div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast(){
  return useContext(ToastContext);
}
