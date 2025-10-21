import { useContext } from 'react';
import ServicesContext from './provider';

export function useServices() {
  return useContext(ServicesContext);
}
