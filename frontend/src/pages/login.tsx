import LoginForm from "../components/auth/LoginForm";
import { useNavigate } from "react-router-dom";

export default function LoginPage() {
  const navigate = useNavigate();
  return (
    <div className="p-6">
      <h1 className="text-2xl font-semibold mb-4">Sign in</h1>
      <LoginForm onSuccess={() => navigate("/dashboard")} />
    </div>
  );
}
