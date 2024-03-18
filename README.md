# Auth-tutorial

[Next Auth V5 - Advanced Guide (2024)](https://www.youtube.com/watch?v=1MTyCvS05V4&t=4990s)을 보고 Next.js에서 로그인을 구현하는 과정을 정리한 레포지토리

# login-form 만들기

## shadcn/ui

form 컴포넌트를 구현하기 위해서 shadcn/ui의 Form 컴포넌트를 사용한다.

```shell
npx shadcn-ui@latest add form
npx shadcn-ui@latest add input
```

[Form 컴포넌트](https://ui.shadcn.com/docs/components/form)를 설치하면 `react-hook-form`과 `zod`가 같이 설치된다.

## zod

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

유효성 검증이 실패했을 경우, 보낼 에러 메시지도 작성할 수 있다.

## 컴포넌트 구성

`LoginForm` 컴포넌트를 작성한다.

[shadcn/ui 문서](https://ui.shadcn.com/docs/components/form)에 따르면 Form 컴포넌트는 아래와 같이 구성된다.

```tsx
return (
  <Form {...form}>
    <form onSubmit={form.handleSubmit(onSubmit)} className='space-y-8'>
      <FormField
        control={form.control}
        name='username'
        render={({ field }) => (
          <FormItem>
            <FormLabel>Username</FormLabel>
            <FormControl>
              <Input placeholder='shadcn' {...field} />
            </FormControl>
            <FormDescription>This is your public display name.</FormDescription>
            <FormMessage />
          </FormItem>
        )}
      />
      <Button type='submit'>Submit</Button>
    </form>
  </Form>
);
```

이제 form과 onsubmit에 대해서 알아보자.

`react-hook-form`의 useForm을 사용해 form 객체를 만들 수 있다.

zod를 사용해 만든 스키마를 사용하여 타입을 추론할 수 있다.

그리고 defaultValues도 넣어줄 수 있다.

로그인을 할 때, 이메일과 패스워드를 넣어줄 것이기 때문에 작성한다.

```tsx
const form = useForm<z.infer<typeof LoginSchema>>({
  resolver: zodResolver(LoginSchema),
  defaultValues: {
    email: '',
    password: '',
  },
});
```

아직 onSubmit을 채우지는 않았지만, values에는 zod를 사용해 타입과 유효성이 검증된 값들이 전달된다.

검증이 실패했다면 onSubmit은 작동하지 않고 `FormMessage` 컴포넌트에서 스키마에 작성한 에러 메시지가 노출될 것이다.

```tsx
const onSubmit = (values: z.infer<typeof LoginSchema>) => {
  // ✅ This will be type-safe and validated.
};
```

## Server Actions

서버 액션은 비동기 함수로 서버에서 실행된다.

Next.js에서 폼 제출과 데이터 mutation을 다루기 위해 서버 컴포넌트와 클라이언트 컴포넌트에서 사용할 수 있다.

서버 액션을 작성하려면 코드 맨 위에 [`use server`](https://react.dev/reference/react/use-server#serializable-parameters-and-return-values)를 추가하면 된다.

서버 액션은 form의 action이나 이벤트 핸들러에서 사용할 수 있다.

먼저 서버 액션을 작성해보자.

이때 클라이언트에서 유효성 검증을 하기는 했지만 서버에서도 한번 더 진행한다.

```ts
// actions/login.ts
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

## 이벤트 핸들러와 서버 액션

이벤트 핸들러에서 서버 액션을 사용하려면 `transition`을 사용해야 한다.

```ts
// login-form.tsx

const [isPending, startTransition] = useTransition();

const onSubmit = (values: z.infer<typeof LoginSchema>) => {
  setError('');
  setSuccess('');
  startTransition(async () => {
    const data = await login(values);
    setError(data?.error);
    setSuccess(data?.success);
  });
};
```

이벤트 핸들러는 아까 본 form 엘리먼트에 전달된다.

그리고 isPending 변수를 Input 컴포넌트의 disabled에 전달해서 폼이 제출동안 입력 받지 못하도록 하면 된다.

```tsx
<form onSubmit={form.handleSubmit(onSubmit)}>...</form>
```

# register-form 만들기

login-form과 거의 동일하게 작성하면 된다.

다만, 서버 액션의 동작이 조금 다르다.

입력 받은 데이터를 토대로 데이터베이스에 새로 사용자를 만들어야 한다. (actions/register.ts를 참고한다.)

# Database & Prisma setup

데이터베이스를 만들고 ORM인 Prisma를 사용하여 접근할 수 있도록 세팅한다.

## 프리즈마 설치 및 세팅

```shell
npm i -D prisma
npm i @prisma/client
```

개발 환경에서 파일을 변경하고 저장하면 next.js는 핫리로드를 하는데, 이때마다 prismaclient를 생성하면 너무 많이 생성한다고 에러가 발생한다.

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

## 데이터베이스 확인하기

neon.tech에 접속하지 않고도 데이터베이스를 확인할 수 있다.

```shell
npx prisma studio
```

# 패스워드 암호화

패스워드를 암호화하기 위해 `bcrypt`를 설치한다.

```shell
npm i bcrypt
npm i -D @types/bcrypt
```

입력 받은 패스워드를 솔트를 넣어서 해싱을 한다.

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

  // 이미 존재하는 유저인지 확인한다.
  const existingUser = await getUserByEmail(email);
  if (existingUser) return { error: 'Email already in use!' };

  // 솔트를 추가하여 해싱한다.
  const hashedPassword = await bcrypt.hash(password, 10);

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

# Auth.js

`Auth.js`를 사용하여 토큰을 사용한 방식으로 로그인을 구현할 수 있다.

## 설치

```shell
npm install next-auth@beta
```

## auth.ts, auth.config.ts, middleware.ts

앞으로 4개의 파일들을 생성할 것이다.

- auth.ts: Auth.js의 핵심 로직을 만드는 곳
- auth.config.ts: Prisma가 Edge 환경에서 작동하지 않기 때문에 만드는 파일.
- route.ts: API endpoint
- middleware.ts: 특정 주소에 접속하면 먼저 실행되는 함수를 정의해두는 곳

먼저 auth.ts를 생성한다.

```ts
import NextAuth from 'next-auth';
import GitHub from 'next-auth/providers/github';

export const {
  handlers: { GET, POST },
  auth,
} = NextAuth({});
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
import type { NextAuthConfig } from 'next-auth';

export default {
  providers: [],
} satisfies NextAuthConfig;
```

이제 auth.config.ts 파일의 내용을 auth.ts에 넣어줄 것이다.

jwt를 사용하기 위해서 https://generate-secret.vercel.app/32 에 가서 시크릿 키를 만들고

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

퍼블릭과 인증이 필요한 페이지 등에 대한 정보를 적어두기 위해 routes.ts를 만든다.

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

export const config = {
  // 여기에 적힌 주소에 접속하면 위의 auth 함수가 실행된다.
  matcher: ['/((?!.+\\.[\\w]+$|_next).*)', '/', '/(api|trpc)(.*)'],
};
```

## Credentials provider

credentials provider를 사용하여 로그인을 하는 작업을 진행한다.

이메일을 통해 사용자를 확인하고, 패스워드를 비교하여 일치하는지 확인한다.

bcrypt가 작동하지 않으면 bcryptjs를 설치한다.

```shell
npm i bcrypt
npm i -D @types/bcryptjs
```

provider는 auth.config.ts에 작성하고 auth.ts에 넣어주는 로직으로 작동한다.

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

auth.ts에 auth.config.ts를 넣어주고 signIn과 signOut을 추가한다.

signIn과 singOut을 사용해 사용자는 로그인과 로그아웃을 할 수 있게 된다.

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

## 로그인

login.ts에서 signIn을 사용한다.

```ts
'use server';

import * as z from 'zod';
import { AuthError } from 'next-auth';
import { LoginSchema } from '@/schemas';
import { signIn } from '@/auth';
import { DEFAULT_LOGIN_REDIRECT } from '@/routes';

export async function login(values: z.infer<typeof LoginSchema>) {
  const validatedFields = LoginSchema.safeParse(values);
  if (!validatedFields.success) return { error: 'Invalid fields!' };

  const { email, password } = validatedFields.data;

  try {
    // 로그인을 진행한다.
    await signIn('credentials', {
      email,
      password,
      redirectTo: DEFAULT_LOGIN_REDIRECT,
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

## 로그아웃

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

auth.ts의 callbacks 에서는 특정 로직이 수행될 때 실행되는 함수를 정의할 수 있다.

## jwt 콜백

`auth.ts`의 jwt 콜백은 JSON 웹 토큰이 생성되거나(i.e. sign in) 업데이트 될 때(i.e. 클라이언트에서 세션에 접근할 때) 호출된다.

반환 값은 암호화되고, 쿠키에 저장된다.

## session 콜백

session 콜백은 세션이 확인될 때마다 호출된다.

기본적으로 토큰의 서브셋만 보안을 위해 반환된다.

만약 jwt() 콜백을 통해 추가한 항목들을 사용가능하게 하려면, 클라이언트에서 사용할 수 있도록 여기서 명시적으로 전달한다.

다시 설명하면, session()에서 session을 반환할 때, token에는 있지만 session에는 없는 값을 추가할 수 있다.

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

스키마를 수정하여 추가 정보를 입력할 수 있다.

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

# OAUTH provider

OAUTH 프로바이더를 사용해 소셜 로그인을 할 수 있다.

```ts
export default {
  providers: [
    Github({
      clientId: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
    }),
    Google({
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    }),
    Credentials({...})
  ]
} satisfies NextAuthConfig;
```

## Github

Settings -> Developer settings -> OAuth Apps 클릭

- Application name: auth-tutorial
- Homepage URL: http://localhost:3000
- Authorization callback URL: http://localhost:3000/api/auth/callback/github

클라이언트 아이디와 시크릿을 .env에 넣는다.

```
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=
```

## Google

[Google Cloud Platform](https://console.cloud.google.com/)에 접속

3:24분 부터

TODO: 계정 추가 문제 발생. 나중에 해결해보기

## 로그인

`import { signIn } from '@/auth'`는 서버 컴포넌트나 서버 액션에서만 사용할 수 있는데,

`import { signIn } from 'next-auth/react'`는 클라이언트 컴포넌트에서 사용할 수 있다.

```ts
// social.tsx

'use client';

import { FcGoogle } from 'react-icons/fc';
import { FaGithub } from 'react-icons/fa';
import { Button } from '@/components/ui/button';
import { signIn } from 'next-auth/react';
import { DEFAULT_LOGIN_REDIRECT } from '@/routes';

export function Social() {
  const onClick = (provider: 'google' | 'github') => {
    signIn(provider, {
      callbackUrl: DEFAULT_LOGIN_REDIRECT,
    });
  };

  return (
    <div className='flex items-center w-full gap-x-2'>
      <Button
        size='lg'
        className='w-full'
        variant='outline'
        onClick={() => onClick('google')}
      >
        <FcGoogle className='h-5 w-5' />
      </Button>
      <Button
        size='lg'
        className='w-full'
        variant='outline'
        onClick={() => onClick('github')}
      >
        <FaGithub className='h-5 w-5' />
      </Button>
    </div>
  );
}
```

이제 깃헙, 구글 버튼을 누르면 로그인 할 수 있게 된다.

그리고 데이터베이스를 확인해보면 (npx prisma studio), 소셜 로그인 계정이 들어있는 것을 확인할 수 있다.

그런데 구글이나 깃헙을 같은 이메일로 만들었다면 로그인이 안될 것이니 다른 계정으로 접속해야한다.

## emailVerified

OAuth로 로그인하면 이메일은 이미 확인된 것이므로 `emailVerified` 필드를 현재 시간으로 설정한다.

여기서는 auth.js의 events를 사용한다.

events는 비동기 함수로 응답을 반환하지 않지만, 로그를 기록하거나 사이드이펙트를 다룰 때 사용한다.

linkAccount 이벤트는 OAuth 프로바이더가 새로운 사용자의 계정을 생성하거나 로그인할 때 발생한다.

```ts
// auth.ts
  events: {
    // OAuth 프로바이더가 계정을 생성하거나 로그인할 때 동작한다.
    // emailVerified 필드를 현재 시간으로 설정한다.
    async linkAccount({ user }) {
      await db.user.update({
        where: { id: user.id },
        data: { emailVerified: new Date() },
      });
    },
  },
```

## 커스텀 에러 페이지 만들기

auth.ts에 error 발생 시 이동할 페이지를 만들어주면 된다.

```ts
// auth.ts
  pages: {
    signIn: '/auth/login',
    error: '/auth/error',
  },
```

그리고 routes.ts의 authRoutes에 추가해준다.

```ts
export const authRoutes = ['/auth/login', '/auth/register', '/auth/error'];
```

## OAuth 이메일 중복 문제

그런데 구글이나 깃헙을 같은 이메일로 만들었다면 로그인이 안될 것이니 다른 계정으로 접속해야한다.

이를 사용자에게 알려주려면 다음과 같이 한다.

1. import { useSearchParams } from 'next/navigation';을 사용해서
2. searchParams가 error인 것을 찾고
3. OAuthAccountNotLinked와 같은지 확인한다.
4. 사용자에게 보여준다.

```ts
const searchParams = useSearchParams();
const urlError =
  searchParams.get('error') === 'OAuthAccountNotLinked'
    ? 'Email already in use with diffrent provider!'
    : '';
```

# email 인증

credentials 로그인을 했다면 이메일을 확인하는 절차를 거쳐야한다.

## 토큰 생성

이메일 인증을 확인하는 토큰을 만들기 위해 스키마를 수정한다.

```
model VerificationToken {
  id String @id @default(cuid())
  email String
  token String @unique
  expires DateTime

  @@unique([email, token])
}
```

```shell
npx prisma generate
npx prisma db push
```

lib/tokens.ts를 작성하여 토큰을 생성하는 함수를 만든다.

```shell
npm i uuid
npm i -D @types/uuid
```

```ts
// lib/tokens.ts
import { db } from './db';
import { getVerificationTokenByEmail } from '@/data/verification-token';
import { v4 as uuidv4 } from 'uuid';

export async function generateVerificationToken(email: string) {
  const token = uuidv4();
  const expires = new Date(new Date().getTime() + 3600 * 1000); // 1 hour
  const existingToken = await getVerificationTokenByEmail(email);

  if (existingToken) {
    await db.verificationToken.delete({
      where: {
        id: existingToken.id,
      },
    });
  }

  const verificationToken = await db.verificationToken.create({
    data: {
      email,
      token,
      expires,
    },
  });

  return verificationToken;
}
```

## 이메일 인증 확인하기

로그인을 하면 일단 데이터베이스에 있는 계정인지 확인한다. (login.ts)

그리고 이메일이 인증되었는지 확인한다.

안되었으면 인증 이메일을 보낸다. (나중에 구현할 것)

## signIn 콜백

다시 auth.ts로 돌아가서 signIn 콜백을 작성한다.

OAuth로 로그인 했으면 그냥 통과시킨다.

emailVerified가 안되어 있으면 false를 반환한다.

이 콜백은 없어도 동작하지만 보안을 위해 fallback으로 만들어 둔 것이라고 설명하는 듯 하다.

```ts
    async signIn({ user, account }) {
      // Allow OAuth without email verification
      if (account?.provider !== 'credentials') return true;
      const existingUser = await getUserById(user.id ?? '');
      // prevent sign in without email verfication
      if (!existingUser?.emailVerified) return false;
      // TODO: Add 2FA check
      return true;
    },
```

## Resend

[Resend](resend.com)에 접속하여 로그인하고 team을 만든다.

[문서](https://resend.com/docs/send-with-nextjs)를 보고 진행하면 된다.

```shell
npm i resend
```

```
// .env
RESEND_API_KEY=...
```

lib/mail.ts를 만들어서 이메일을 전송한다.

```ts
import { Resend } from 'resend';

const resend = new Resend(process.env.RESEND_API_KEY);

export async function sendVerificationEmail(email: string, token: string) {
  // 배포 후 수정한다.
  const confirmLink = `http://localhost:3000/auth/new-verification?token=${token}`;

  await resend.emails.send({
    from: 'onboarding@resend.dev',
    to: email,
    subject: 'Confirm your email',
    html: `<p>Click <a href="${confirmLink}">here</a> to confirm email.</p>`,
  });
}
```

계정을 만들때 인증 이메일을 보낸다.

```ts
// register.ts

// verification 토큰을 생성하고
const verificationToken = await generateVerificationToken(email);
// 이메일을 보낸다.
await sendVerificationEmail(verificationToken.email, verificationToken.token);
```

이메일 인증을 하지 않은 사용자가 로그인할 경우도 대비한다.

```ts
// login.ts

if (!existingUser.emailVerified) {
  const verificationToken = await generateVerificationToken(existingUser.email);
  await sendVerificationEmail(verificationToken.email, verificationToken.token);

  return { success: 'Confirmation email sent' };
}
```

## public route 추가 & 페이지 만들기 & 서버 액션

이메일의 링크를 클릭하고 접속하는 곳을 public에 추가한다.

```ts
// route.ts
export const publicRoutes = ['/', '/auth/new-verification'];
```
