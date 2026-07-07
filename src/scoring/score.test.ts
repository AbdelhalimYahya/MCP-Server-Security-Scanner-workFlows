import { describe, it, expect } from 'vitest';
import type { Finding } from '../types.js';
import { calculateScore } from './score.js';

function finding(severity: Finding['severity']): Finding {
  return {
    id: 'TEST',
    severity,
    title: 'test',
    description: 'test',
    file: 'test.ts',
    recommendation: 'fix it',
  };
}

describe('calculateScore', () => {
  it('zero findings — 100 points, grade A', () => {
    const result = calculateScore([]);
    expect(result.score).toBe(100);
    expect(result.grade).toBe('A');
  });

  it('one critical finding — 75 points, grade B', () => {
    const result = calculateScore([finding('critical')]);
    expect(result.score).toBe(75);
    expect(result.grade).toBe('B');
  });

  it('one high finding — 88 points, grade B', () => {
    const result = calculateScore([finding('high')]);
    expect(result.score).toBe(88);
    expect(result.grade).toBe('B');
  });

  it('one medium finding — 95 points, grade A', () => {
    const result = calculateScore([finding('medium')]);
    expect(result.score).toBe(95);
    expect(result.grade).toBe('A');
  });

  it('one low finding — 98 points, grade A', () => {
    const result = calculateScore([finding('low')]);
    expect(result.score).toBe(98);
    expect(result.grade).toBe('A');
  });

  it('info findings cost no points', () => {
    const result = calculateScore([finding('info'), finding('info'), finding('info')]);
    expect(result.score).toBe(100);
    expect(result.grade).toBe('A');
  });

  it('score floors at 0, never negative', () => {
    const result = calculateScore([
      finding('critical'),
      finding('critical'),
      finding('critical'),
      finding('critical'),
      finding('critical'),
    ]);
    expect(result.score).toBe(0);
    expect(result.grade).toBe('F');
  });

  it('low-severity cap at -10 (20 low findings)', () => {
    const result = calculateScore(Array.from({ length: 20 }, () => finding('low')));
    expect(result.score).toBe(90);
    expect(result.grade).toBe('A');
  });

  it('low-severity cap stacks with other deductions', () => {
    const result = calculateScore([
      finding('critical'),
      ...Array.from({ length: 20 }, () => finding('low')),
    ]);
    expect(result.score).toBe(65);
    expect(result.grade).toBe('C');
  });

  it('mixed findings land in D grade', () => {
    const result = calculateScore([
      finding('critical'),
      finding('critical'),
      finding('high'),
      finding('medium'),
    ]);
    expect(result.score).toBe(100 - 25 - 25 - 12 - 5);
    expect(result.score).toBe(33);
    expect(result.grade).toBe('F');
  });

  it('mixed findings land in C grade', () => {
    const result = calculateScore([finding('critical'), finding('medium')]);
    expect(result.score).toBe(70);
    expect(result.grade).toBe('C');
  });

  it('one critical + many low — lands in B', () => {
    const result = calculateScore([
      finding('critical'),
      ...Array.from({ length: 3 }, () => finding('low')),
    ]);
    expect(result.score).toBe(100 - 25 - Math.min(6, 10));
    expect(result.score).toBe(69);
    expect(result.grade).toBe('C');
  });
});
