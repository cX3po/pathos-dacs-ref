// Internal worker: the public CLI parent enforces the hard process deadline.
import {main} from './main.mjs';
try {process.exit(await main());} catch {console.error('recipe-studio: invalid input or operation failed (use --help)');process.exit(2);}
