import { Backend_URL } from "@/lib/Constants";
import { NextAuthOptions } from "next-auth";
import { JWT } from "next-auth/jwt";
import NextAuth from "next-auth/next";
import CredentialsProvider from "next-auth/providers/credentials";

async function refreshToken(token: JWT): Promise<JWT> {
  const res = await fetch(Backend_URL + "/auth/refresh", {
    method: "POST",
    headers: {
      authorization: `Refresh ${token.backendTokens.refreshToken}`,
    },
  });
  console.log("refreshed");

  const response = await res.json();

  return {
    ...token,
    backendTokens: response,
  };
}

export const authOptions: NextAuthOptions = {
  providers: [
    CredentialsProvider({
      name: "Credentials",
      credentials: {
        username: {
          label: "Username",
          type: "text",
          placeholder: "Enter your username.",
        },
        password: { label: "Password", type: "password" },
      },

      // after click submit button that will do this async function
      async authorize(credentials, req) {
        if (!credentials?.username || !credentials?.password) return null;
        const { username, password } = credentials;
        const res = await fetch(Backend_URL + "/auth/login", {
          method: "POST",
          body: JSON.stringify({
            username,
            password,
          }),
          headers: {
            "Content-Type": "application/json",
          },
        });
        if (res.status == 401) {
          console.log("\n\n\nres.statusText", res.statusText, "\n\n\n");

          return null;
        }
        const user = await res.json();
        return user;
      },
    }),
  ],

  // performed when user sign in and then callback will do
  callbacks: {
    // jwt callback will be called and it recieve token and user,the last will return token
    async jwt({ token, user }) {
      // console.log("\n\n\nuser", user, "\n\n\n");
      if (user) return { ...token, ...user };

      if (new Date().getTime() < token.backendTokens.expiresIn) return token;

      return await refreshToken(token);
    },

    // every time when this session will be get by useSession or get server session func
    // session callback will recieve data from token of jwt callback
    async session({ token, session }) {
      session.user = token.user;
      session.backendTokens = token.backendTokens;
      // console.log("\n\n\n session", session, "\n\n\n");
      return session;
    },
  },
  secret: process.env.NEXTAUTH_SECRET,
};

const handler = NextAuth(authOptions);

export { handler as GET, handler as POST };
