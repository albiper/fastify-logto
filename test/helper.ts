'use strict'

import fastify from 'fastify';
import { Test } from 'tap';
import { LogtoFastifyConfig } from '../src';
import FastLogTo from '../src/index.js';


export const adminSecret = 'admin';
export const logtoBaseConfig: LogtoFastifyConfig = {
  endpoint: 'http://localhost:3001',
  appId: 'x33chy0wqu70iwr1is2i0', // Replace with your own appId
  appSecret: 'lQ7Jnme0z4xrlzAWPIAFirxjQAVf34xU', // Replace with your own appSecret
}

export async function getServer(t: Test) {
  const server = fastify();
  server.register(FastLogTo, logtoBaseConfig);

  return server
}
