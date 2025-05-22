import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

declare module 'next/server' {
  interface NextRequest {
    ip?: string
  }
}

export function middleware(request: NextRequest) {
  const { pathname, search } = request.nextUrl;
  const forwarded = request.headers.get('x-forwarded-for');
  (request as any).ip = forwarded ? forwarded.split(',')[0] : request.socket?.remoteAddress;

  console.log(`Incoming request: ${pathname}${search}`);

  if (pathname.endsWith('.php')) {
    const url = request.nextUrl.clone();
    url.pathname = '/api/secureproxy';
    url.search = search;
    return NextResponse.rewrite(url);
  }

  return NextResponse.next();
}

export const config = {
  matcher: ['/secureproxy.php'],
};