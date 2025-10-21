import type { MedicalRecord, Prisma } from '@prisma/client';

export interface IMedicalRecordService {
  list(take?: number): Promise<MedicalRecord[]>;
  create(data: Prisma.MedicalRecordCreateInput | Prisma.MedicalRecordUncheckedCreateInput): Promise<MedicalRecord>;
  getById(id: string): Promise<MedicalRecord | null>;
  update(id: string, data: Prisma.MedicalRecordUpdateInput | Prisma.MedicalRecordUncheckedUpdateInput): Promise<MedicalRecord>;
  delete(id: string): Promise<MedicalRecord>;
}

export default IMedicalRecordService;
