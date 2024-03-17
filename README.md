# Auth-tutorial

[Next Auth V5 - Advanced Guide (2024)](https://www.youtube.com/watch?v=1MTyCvS05V4&t=4990s)을 보고 Next.js에서 로그인을 구현하는 과정을 정리한 레포지토리

# 로그인/등록 폼 구현

로그인과 계정 등록 폼의 구현은 거의 동일하므로 로그인 폼 구현 과정을 정리해본다.

`app/components/auth/login-form.tsx`를 참고한다.

## shadcn/ui

shadcn/ui에서 Form 컴포넌트를 설치한다.

이때 `react-hook-form`과 `zod`가 같이 설치된다.

```shell
npx shadcn-ui@latest add form
```

shandcn/ui의 input 컴포넌트도 설치해준다.

```shell
npx shadcn-ui@latest add input
```

## zod 스키마

로그인 필드의 유효성을 검증하기 위해서 zod를 사용해 로그인 스키마를 작성한다.

```ts
// @/schemas/index.ts
import * as z from 'zod';

export const LoginSchema = z.object({
  email: z.string().email({
    message: 'Email is required',
  }),
  password: z.string().min(1, { message: 'Password is required' }),
});
```

## 로그인 폼 컴포넌트 구성

이제 아래와 같이 `LoginForm` 컴포넌트를 구성한다.

```tsx
import * as z from 'zod';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';

import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';

export function LoginForm() {

  /* react-hook-form의 useForm과 zod의 infer 기능을 사용해서 유효성을 검증한다. */
  const form = useForm<z.infer<typeof LoginSchema>>({
    resolver: zodResolver(LoginSchema),
    defaultValues: {
      email: '',
      password: '',
    },
  });

  const onSubmit = (values: z.infer<typeof LoginSchema>) => {
	//console.log(values);
  };

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)}>
        <FormField
          <FormLabel>...</FormLabel>
          <FormCotrol>
            <Input ... />
          </FormControl>
        />
        /* FormField */
      </form>
    </Form>
  )
}
```

## server action을 사용한다.

폼은 `server action`을 사용해 서버에서 제출되도록 한다.

이 기능은 특정 함수 실행 그 자체를 서버에서 수행할 수 있도록 해준다.

클라이언트에서의 유효성 검증은 믿을 수 없으므로 검증은 다시 해야 한다.

```ts
// actions.ts
'use server';

import * as z from 'zod';
import { LoginSchema } from '@/schemas';

export async function login(values: z.infer<typeof LoginSchema>) {
  // 유효성을 검증한다.
  const validatedFields = LoginSchema.safeParse(values);
  if (!validatedFields.success) return { error: 'Invalid fields!' };
  return { success: 'Email sent!' };
}
```

## onSubmit을 작성한다.

`useTransition`에서 제공하는 `startTranstion`에 서버 액션을 실행한다.

```ts
const onSubmit = (values: z.infer<typeof LoginSchema>) => {
  setError('');
  setSuccess('');
  startTransition(() => {
    login(values).then((data) => {
      setError(data.error);
      setSuccess(data.success);
    });
  });
};
```

# Database & Prisma setup

데이터베이스를 만들고 ORM인 Prisma를 사용하여 접근할 수 있도록 세팅한다.

## 프리즈마 설치 및 세팅

```shell
npm i -D prisma
npm i @prisma/client
```

개발 환경에서 파일을 변경하고 저장하면 next.js는 핫리로드를 하는데,

이때마다 prismaclient를 생성하면 너무 많이 생성한다고 에러가 발생한다.

따라서 프로덕션이 아니라면 globalThis에 db를 저장한다.

globalThis는 핫 리로드에 영향을 받지 않기 때문에 가능하다.

```ts
// lib/db.ts
import { PrismaClient } from '@prisma/client';

declare global {
  var prisma: PrismaClient | undefined;
}

export const db = globalThis.prisma || new PrismaClient();

if (process.env.NODE_ENV !== 'production') globalThis.prisma = db;
```

그리고 환경 변수를 깃허브에 업로드 하지 않기 위해 `.gitignore`에 다음을 추가한다.

```
.env
```

마지막으로 다음을 입력하면 끝

```shell
npx prisma init
```

## 데이터베이스 얻기

[neon.tech](neon.tech)에 접속하여 프로젝트를 생성하고 무료 postgresqlDB를 얻는다.

## 스키마 작성하기

neon.tech에서 프로젝트를 생성했으면 스키마와 .env 파일에 들어갈 내용이 나온다.

env는 복사 후 붙여 넣는다.

스키마는 아래와 같이 작성한다.

[Auth.js](https://authjs.dev/reference/adapter/prisma)를 참고해서 작성하면 된다.

```prisma
// prisma/schema.prisma
datasource db {
  provider  = "postgresql"
  url  	    = env("DATABASE_URL")
}

generator client {
  provider = "prisma-client-js"
}

model User {
  id            String    @id @default(cuid())
  name          String?
  email         String?   @unique
  emailVerified DateTime?
  image         String?
  password      String?
  accounts      Account[]
}

model Account {
  id                 String  @id @default(cuid())
  userId             String
  type               String
  provider           String
  providerAccountId  String
  refresh_token      String?  @db.Text
  access_token       String?  @db.Text
  expires_at         Int?
  token_type         String?
  scope              String?
  id_token           String?  @db.Text
  session_state      String?

  user User @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@unique([provider, providerAccountId])
}
```

## 데이터베이스 동기화

이제 데이터베이스를 동기화하고 프리즈마 어댑터를 생성해보자

```shell
npm i @auth/prisma-adapter
npx prisma generate
npx prisma db push
```

# 패스워드 암호화

패스워드를 암호화하기 위해 `bcrypt`를 설치한다.

```shell
npm i bcrypt
npm i -D @types/bcrypt
```

패스워드를 솔트를 넣어서 해싱을 한다.

```ts
// actions/register.ts
'use server';

import * as z from 'zod';
import bcrypt from 'bcrypt';

import { db } from '@/lib/db';
import { RegisterSchema } from '@/schemas';
import { getUserByEmail } from '@/data/user';

export async function register(values: z.infer<typeof RegisterSchema>) {
  const validatedFields = RegisterSchema.safeParse(values);
  if (!validatedFields.success) return { error: 'Invalid fields!' };

  const { email, password, name } = validatedFields.data;
  // 솔트를 추가하여 해싱한다.
  const hashedPassword = await bcrypt.hash(password, 10);

  const existingUser = await getUserByEmail(email);

  // 이미 존재하는 유저인지 확인한다.
  if (existingUser) return { error: 'Email already in use!' };

  // 새로운 계정을 생성한다.
  await db.user.create({
    data: {
      name,
      email,
      password: hashedPassword,
    },
  });

  // TODO: Send verification token email

  return { success: 'User created!' };
}
```

자주 가져오는 로직은 따로 만들어둔다.

```ts
// data/user.ts
import { db } from '@/lib/db';

export async function getUserByEmail(email: string) {
  try {
    const user = db.user.findUnique({
      where: { email },
    });
    return user;
  } catch {
    return null;
  }
}

export async function getUserById(id: string) {
  try {
    const user = db.user.findUnique({
      where: { id },
    });
    return user;
  } catch {
    return null;
  }
}
```

# Auth.js

`Auth.js`를 사용하여 로그인을 구현할 수 있다.

```shell
npm install next-auth@beta
```

## auth.ts, auth.config.ts, middleware.ts

auth.ts를 생성한다.

```ts
// https://authjs.dev/guides/upgrade-to-v5
import NextAuth from 'next-auth';
import GitHub from 'next-auth/providers/github';

export const {
  handlers: { GET, POST },
  auth,
} = NextAuth({
  providers: [GitHub],
});
```

route.ts도 생성한다.

```ts
// app/api/auth/[...nextauth]/route.ts
export { GET, POST } from '@/auth';
```

http://localhost:3000/api/auth/providers 가 잘 나오면 성공이다.

middleware.ts도 생성한다.

```ts
import { auth } from './auth';

export default auth((req) => {
  // req.auth
  console.log('ROUTE: ', req.nextUrl.pathname);
});

// Optionally, don't invoke Middleware on some paths
export const config = {
  // 여기에 적힌 주소에 접속하면 위의 auth 함수가 실행된다.
  matcher: ['/((?!.+\\.[\\w]+$|_next).*)', '/', '/(api|trpc)(.*)'],
};
```

프리즈마는 아직 Edge를 지원하지 않기 때문에 auth.config.ts를 생성하고 다음을 작성한다.

```ts
// auth.config.ts
import GitHub from 'next-auth/providers/github';

import type { NextAuthConfig } from 'next-auth';

export default {
  providers: [GitHub],
} satisfies NextAuthConfig;
```

https://generate-secret.vercel.app/32 에 가서 시크릿 키를 만들고

.env에 AUTH_SECRET 변수를 만든다.

그리고 auth.ts를 다음과 같이 수정한다.

```ts
import NextAuth from 'next-auth';
import { PrismaAdapter } from '@auth/prisma-adapter';

import { db } from '@/lib/db';
import authConfig from '@/auth.config';

export const {
  handlers: { GET, POST },
  auth,
  signIn,
  signOut,
} = NextAuth({
  adapter: PrismaAdapter(db),
  secret: process.env.AUTH_SECRET,
  session: { strategy: 'jwt' },
  ...authConfig,
});
```

## 로그인 인증이 필요한 페이지 만들기

routes.ts를 생성한다.

여기에는 퍼블릭과 인증이 필요한 페이지등에 대한 정보를 적어둔다.

```ts
/**
 * An array of routes that are accessible to the public
 * These routes do not require authentication
 * @type {string[]}
 */
export const publicRoutes = ['/'];

/**
 * An array of routes that are used for authentication
 * These routes will redirect logged in users to /settings
 * @type {string[]}
 */
export const authRoutes = ['/auth/login', '/auth/register'];

/**
 * The prefix for API authentication routes
 * Routes that start with this prefix are used for API authentication purposes.
 * @type {string}
 */
export const apiAuthPrefix = '/api/auth';

/**
 * The default redirect path after logging in
 * @type {string}
 */
export const DEFAULT_LOGGIN_REDIRECT = '/settings';
```

그리고 middleware.ts에서 다음과 같이 인증이 필요한 페이지에 로그인 하지 않고 접속하면 다른 페이지로 리다이렉트 하도록 만든다.

여기서 /settings로 접속하면 로그인도 안했고 퍼블릭 라우트도 아니기 때문에 /auth/login로 리다이렉트 된다.

```ts
import NextAuth from 'next-auth';
import authConfig from '@/auth.config';
import {
  DEFAULT_LOGGIN_REDIRECT,
  apiAuthPrefix,
  authRoutes,
  publicRoutes,
} from '@/routes';

const { auth } = NextAuth(authConfig);

export default auth((req) => {
  const { nextUrl } = req;
  const isLoggedIn = !!req.auth;

  const isApiAuthRoute = nextUrl.pathname.startsWith(apiAuthPrefix);
  const isPublicRoute = publicRoutes.includes(nextUrl.pathname);
  const isAuthRoute = authRoutes.includes(nextUrl.pathname);

  if (isApiAuthRoute) return null;
  if (isAuthRoute) {
    if (isLoggedIn)
      return Response.redirect(new URL(DEFAULT_LOGGIN_REDIRECT, nextUrl));
    return null;
  }
  if (!isLoggedIn && !isPublicRoute)
    return Response.redirect(new URL('/auth/login', nextUrl));
  return null;
});

// Optionally, don't invoke Middleware on some paths
export const config = {
  // 여기에 적힌 주소에 접속하면 위의 auth 함수가 실행된다.
  matcher: ['/((?!.+\\.[\\w]+$|_next).*)', '/', '/(api|trpc)(.*)'],
};
```

## 로그인 하기

credentials provider를 사용하여 로그인을 하는 작업을 진행한다.

이메일을 통해 사용자를 확인하고, 패스워드를 비교하여 일치하는지 확인한다.

bcrypt가 작동하지 않으면 bcryptjs를 설치한다.

```shell
npm i bcrypt
npm i -D @types/bcryptjs
```

```ts
// auth.config.ts
import type { NextAuthConfig } from 'next-auth';
import Credentials from 'next-auth/providers/credentials';
import bcrypt from 'bcryptjs';

import { LoginSchema } from '@/schemas';
import { getUserByEmail } from '@/data/user';

export default {
  providers: [
    Credentials({
      async authorize(credentials) {
        const validatedFields = LoginSchema.safeParse(credentials);
        if (!validatedFields.success) return null;

        const { email, password } = validatedFields.data;
        const user = await getUserByEmail(email);
        // 사용자를 확인한다.
        if (!user || !user.password) return null;
        const passwordMatch = await bcrypt.compare(password, user.password);

        if (passwordMatch) return user;
        return null;
      },
    }),
  ],
} satisfies NextAuthConfig;
```

auth.ts에 signIn과 signOut을 추가한다.

```ts
import NextAuth from 'next-auth';
import { PrismaAdapter } from '@auth/prisma-adapter';
import authConfig from '@/auth.config';
import { db } from '@/lib/db';

export const {
  handlers: { GET, POST },
  auth,
  signIn,
  signOut,
} = NextAuth({
  adapter: PrismaAdapter(db),
  session: { strategy: 'jwt' },
  ...authConfig,
});
```

login.ts에서 signIn을 사용한다.

```ts
'use server';

import * as z from 'zod';
import { AuthError } from 'next-auth';
import { LoginSchema } from '@/schemas';
import { signIn } from '@/auth';
import { DEFAULT_LOGGIN_REDIRECT } from '@/routes';

export async function login(values: z.infer<typeof LoginSchema>) {
  const validatedFields = LoginSchema.safeParse(values);
  if (!validatedFields.success) return { error: 'Invalid fields!' };

  const { email, password } = validatedFields.data;

  try {
    // 로그인을 진행한다.
    await signIn('credentials', {
      email,
      password,
      redirectTo: DEFAULT_LOGGIN_REDIRECT,
    });
  } catch (error) {
    // 로그인에 실패하면 에러가 발생한다.
    if (error instanceof AuthError) {
      switch (error.type) {
        case 'CredentialsSignin':
          return { error: 'Invalid credentials' };
        default:
          return { error: 'Something went wrong!' };
      }
    }
    throw error;
  }
}
```

## 로그 아웃 하기

로그인 후 리다이렉트 된 페이지에서 signOut을 사용해 로그 아웃이 가능하다.

```tsx
import { auth, signOut } from '@/auth';

export default async function SettingsPage() {
  const session = await auth();
  return (
    <div>
      {JSON.stringify(session)}
      <form
        action={async () => {
          'use server';
          await signOut();
        }}
      >
        <button type='submit'>Sign out</button>
      </form>
    </div>
  );
}
```

# callbacks

## 데이터베이스 확인하기

neon.tech에 접속하지 않고도 데이터베이스를 확인할 수 있다.

```shell
npx prisma studio
```

## jwt 콜백

`auth.ts`의 jwt 콜백은 JSON 웹 토큰이 생성되거나(i.e. sign in) 업데이트 될 때(i.e. 클라이언트에서 세션에 접근할 때) 호출된다.

반환 값은 암호화되고, 쿠키에 저장된다.

## session 콜백

session 콜백은 세션이 확인될 때마다 호출된다.

기본적으로 토큰의 서브셋만 보안을 위해 반환된다.

만약 jwt() 콜백을 통해 추가한 항목들을 사용가능하게 하려면, 클라이언트에서 사용할 수 있도록 여기서 명시적으로 전달한다.

```ts
import NextAuth from 'next-auth';
import { PrismaAdapter } from '@auth/prisma-adapter';

import { db } from '@/lib/db';
import authConfig from '@/auth.config';

export const {
  handlers: { GET, POST },
  auth,
  signIn,
  signOut,
} = NextAuth({
  callbacks: {
    async session({ token, session }) {
      // token의 일부만을 저장한 것이 session이다.
      // 따라서 session에 token.sub까지 포함시키려면 직접 설정한다.
      if (token.sub && session.user) {
        session.user.id = token.sub;
      }
      return session;
    },
    async jwt({ token }) {
      return token;
    },
  },
  adapter: PrismaAdapter(db),
  secret: process.env.AUTH_SECRET,
  session: { strategy: 'jwt' },
  ...authConfig,
});
```

## session에 커스텀 필드 추가하기

스키마를 수정하여 추가 정보를 입력한다.

```schema
enum UserRole {
  ADMIN
  USER
}

model User {
  id            String    @id @default(cuid())
  name          String?
  email         String?   @unique
  emailVerified DateTime?
  image         String?
  password      String?
  role          UserRole  @default(USER)
  accounts      Account[]
}
```

```shell
npx prisma generate
npx prisma migrate reset
npx prisma db push
```

그리고 jwt 콜백에서 token에 role 필드를 추가하면 sessio 콜백의 token에서 확인할 수 있다.

```ts
import NextAuth from 'next-auth';
import { PrismaAdapter } from '@auth/prisma-adapter';

import { db } from '@/lib/db';
import { getUserById } from '@/data/user';
import authConfig from '@/auth.config';

export const {
  handlers: { GET, POST },
  auth,
  signIn,
  signOut,
} = NextAuth({
  callbacks: {
    async session({ token, session }) {
      if (token.sub && session.user) {
        session.user.id = token.sub;
      }
      // 2. session 콜백의 token에서 role 필드를 확인할 수 있다.
      // 3. session에 token.role을 추가한다.
      // 4. TODO: session typescript 에러 수정하기
      if (token.role && session.user) {
        session.user.role = token.role;
      }
      return session;
    },
    async jwt({ token }) {
      if (!token.sub) return token;
      const existingUser = await getUserById(token.sub);
      if (!existingUser) return token;
      // 1. token에 role 필드를 추가한다.
      token.role = existingUser.role;
      return token;
    },
  },
  adapter: PrismaAdapter(db),
  secret: process.env.AUTH_SECRET,
  session: { strategy: 'jwt' },
  ...authConfig,
});
```

session에 커스텀 필드를 추가하여 타입스크립트 에러가 발생하므로 수정해야 한다.

https://authjs.dev/getting-started/typescript

위 문서를 참고하여 다음과 같이 진행한다.

```ts
import { UserRole } from '@prisma/client';

declare module 'next-auth' {
  interface User {
    /** The user's postal address. */
    role: UserRole;
  }
}

// ...
    async session({ token, session }) {
      if (token.sub && session.user) {
        session.user.id = token.sub;
      }
      if (token.role && session.user) {
        session.user.role = token.role as UserRole;
      }
      return session;
    },
```
