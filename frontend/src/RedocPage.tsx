import React from 'react';
import { RedocStandalone } from 'redoc';

export default function RedocPage(): JSX.Element {
  return (
    <div style={{ height: '100vh' }}>
      <RedocStandalone specUrl="/api-docs/latest/openapi.json" />
    </div>
  );
}
