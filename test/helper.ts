'use strict'

import fastify from 'fastify';
import { Test } from 'tap';
import { LogtoFastifyConfig } from '../src';
import FastLogTo from '../src/index.js';


export const adminSecret = 'admin';
export const logtoBaseConfig: LogtoFastifyConfig = {
  endpoint: 'http://localhost:3001',
  appId: 'kabilkesud6a2m1zllljq',
  appSecret: 'ZWX4bxvHsFfgzbkXJffdHHTcmSj64gLZ', 
}

export async function getServer(t: Test) {
  const server = fastify();
  server.register(FastLogTo, logtoBaseConfig);

  return server
}
