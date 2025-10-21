import RegisterForm from "../components/auth/RegisterForm";
import { useNavigate } from "react-router-dom";

export default function RegisterPage() {
  const navigate = useNavigate();
  return (
    <div className="p-6">
      <h1 className="text-2xl font-semibold mb-4">Create your account</h1>
      <RegisterForm onSuccess={() => navigate("/login")} />
    </div>
  );
}
