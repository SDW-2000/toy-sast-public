import '@testing-library/jest-dom/vitest';
import { beforeEach } from 'vitest';

beforeEach(() => {
  window.sessionStorage.clear();
});
