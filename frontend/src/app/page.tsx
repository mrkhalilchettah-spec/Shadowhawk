/**
 * ShadowHawk Platform Index Redirect
 */
import { redirect } from "next/navigation";

const HomePage = () => {
  redirect("/dashboard");
};

export default HomePage;
