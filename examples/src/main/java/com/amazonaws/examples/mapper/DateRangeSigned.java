package com.amazonaws.examples.mapper;


import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DoNotEncrypt;

import java.util.Date;

public class DateRangeSigned {
  private Date start;
  private Date end;

  public DateRangeSigned(DateRange dateRange) {
    this.start = dateRange.getStart();
    this.end = dateRange.getEnd();
  }

  public DateRangeSigned() {};

  @DoNotEncrypt
  public Date getStart() { return start; }
  public void setStart(Date start) { this.start = start; }

  @DoNotEncrypt
  public Date getEnd() { return end; }
  public void setEnd(Date end) { this.end = end; }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (obj == null) return false;
    if (getClass() != obj.getClass()) return false;
    DateRangeSigned other = (DateRangeSigned) obj;
    if (start == null) {
      if (other.start != null) return false;
    } else if (!start.equals(other.start)) return false;
    if (end == null) {
      if (other.end != null) return false;
    } else if (!end.equals(other.end)) return false;
    return true;
  }

  @Override
  public String toString() {
    return "DateRangeSigned [start=" + start + ", end=" + end +"]";
  }

}
