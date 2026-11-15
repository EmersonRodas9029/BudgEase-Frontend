import toast from 'react-hot-toast';
import { logout } from '../shared/utils';

export const forceLogout = (message = 'Tu sesión expiró. Inicia sesión de nuevo.'): void => {
  logout();
  toast.error(message, { id: 'session-expired' });
  window.location.hash = '/login';
};
