// scripts/chatgpt/auth/pow.js
// Proof-of-Work solver for ChatGPT sentinel challenge

const Encoding = require('../core/encoding.js');
const Fingerprint = require('../config/fingerprint.js');

class ProofOfWork {
    /**
     * Run a single PoW check iteration.
     */
    static runCheck(startTime, seed, difficulty, config, attempt) {
        config[3] = attempt;
        config[9] = Math.round(Date.now() - startTime);
        var r = Encoding.m1(config);
        if (Encoding.fnv1a(seed + r).substring(0, difficulty.length) <= difficulty) {
            return r + '~S';
        }
        return null;
    }

    /**
     * Solve PoW synchronously — brute-force up to 99999 attempts.
     */
    static solve(seed, difficulty) {
        var startTime = Date.now();
        try {
            var config = Fingerprint.getConfig('');
            for (var a = 0; a < 99999; a++) {
                var r = ProofOfWork.runCheck(startTime, seed, difficulty, config, a);
                if (r) return r;
            }
        } catch (err) {
            console.error('[PoW] Failed:', err);
        }
        return null;
    }

    /**
     * Extract seed/difficulty from challenge data and solve.
     * @param {object} challengeData — Sentinel prepare response
     * @returns {string|null} — Prefixed answer or null
     */
    static getAnswer(challengeData) {
        var prefix = 'gAAAAAB';
        if (!challengeData || !challengeData.proofofwork || !challengeData.proofofwork.required) {
            return null;
        }
        var seed = challengeData.proofofwork.seed;
        var difficulty = challengeData.proofofwork.difficulty;
        if (typeof seed !== 'string' || typeof difficulty !== 'string') {
            return null;
        }
        var answer = ProofOfWork.solve(seed, difficulty);
        return answer ? prefix + answer : null;
    }
}

module.exports = ProofOfWork;
