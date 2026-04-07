/**
 * Port allocator — hands out ports from a configured range
 * and tracks which are in use.
 */
export class PortAllocator {
  private readonly min: number;
  private readonly max: number;
  private readonly allocated = new Set<number>();

  constructor(range: [number, number]) {
    this.min = range[0];
    this.max = range[1];
  }

  allocate(): number {
    for (let port = this.min; port <= this.max; port++) {
      if (!this.allocated.has(port)) {
        this.allocated.add(port);
        return port;
      }
    }
    throw new Error(`No ports available in range ${this.min}-${this.max}`);
  }

  release(port: number): void {
    this.allocated.delete(port);
  }

  isAvailable(port: number): boolean {
    return port >= this.min && port <= this.max && !this.allocated.has(port);
  }

  reserve(port: number): void {
    this.allocated.add(port);
  }

  get size(): number {
    return this.allocated.size;
  }
}
