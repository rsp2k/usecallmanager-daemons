import { defineCollection, z } from 'astro:content';

const docs = defineCollection({
  type: 'content',
  schema: z.object({
    title: z.string(),
    description: z.string(),
    order: z.number().optional(),
    category: z.enum(['getting-started', 'api', 'security', 'deployment']).optional(),
    lastUpdated: z.date().optional(),
  }),
});

export const collections = { docs };
