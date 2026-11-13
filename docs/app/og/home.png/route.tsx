import { renderOgImage } from '@/lib/og';

export const revalidate = false;

export async function GET() {
  return renderOgImage({
    eyebrow: 'OIDC policy gateway',
    title: 'Every request passes the gate.',
    description: 'Verify JWTs, bind every OpenAPI operation to an explicit CEL policy, and forward only what you allow.',
  });
}
