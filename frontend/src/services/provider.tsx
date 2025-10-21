import React, { createContext } from 'react';
import type { Services } from './defaults';
import { defaultServices } from './defaults';

const ServicesContext = createContext<Services>(defaultServices);

export function ServicesProvider({ children, services }: React.PropsWithChildren<{ services?: Partial<Services> }>) {
  const merged = { ...defaultServices, ...(services ?? {}) } as Services;
  return <ServicesContext.Provider value={merged}>{children}</ServicesContext.Provider>;
}

export default ServicesContext;
