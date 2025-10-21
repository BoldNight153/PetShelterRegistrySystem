import type { PrismaClient, MedicalRecord, Prisma } from '@prisma/client';
import type { IMedicalRecordService } from './interfaces/medicalRecordService.interface';

export class MedicalRecordService implements IMedicalRecordService {
  prisma: PrismaClient;
  constructor(opts: { prisma: PrismaClient }) {
    this.prisma = opts.prisma;
  }

  async list(take = 500): Promise<MedicalRecord[]> {
    return await this.prisma.medicalRecord.findMany({ take });
  }

  async create(data: Prisma.MedicalRecordCreateInput | Prisma.MedicalRecordUncheckedCreateInput): Promise<MedicalRecord> {
    return this.prisma.medicalRecord.create({ data });
  }

  async getById(id: string): Promise<MedicalRecord | null> {
    return await this.prisma.medicalRecord.findUnique({ where: { id } });
  }

  async update(id: string, data: Prisma.MedicalRecordUpdateInput | Prisma.MedicalRecordUncheckedUpdateInput): Promise<MedicalRecord> {
    return this.prisma.medicalRecord.update({ where: { id }, data });
  }

  async delete(id: string): Promise<MedicalRecord> {
    return await this.prisma.medicalRecord.delete({ where: { id } });
  }
}

export default MedicalRecordService;
